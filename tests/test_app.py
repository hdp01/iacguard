"""Tests for the app's input handling. No AWS calls are made."""

import zipfile

import pytest

import app


def write(path, text=' resource "aws_ebs_volume" "v" { size = 1 }'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# ---------------------------------------------------------------------------
# plain paths
# ---------------------------------------------------------------------------

def test_single_file(tmp_path):
    target = write(tmp_path / "main.tf")
    files, workdir = app.resolve_input(str(target))
    assert files == [target]
    assert workdir is None


def test_directory_is_searched_recursively(tmp_path):
    write(tmp_path / "main.tf")
    write(tmp_path / "modules" / "db" / "nested.tf")
    write(tmp_path / "notes.txt", "not terraform")
    files, _ = app.resolve_input(str(tmp_path))
    assert [f.name for f in files] == ["nested.tf", "main.tf"] or \
           sorted(f.name for f in files) == ["main.tf", "nested.tf"]
    assert all(f.suffix == ".tf" for f in files)


def test_quoted_and_padded_paths_are_accepted(tmp_path):
    """Users paste paths with quotes from file managers more often than not."""
    target = write(tmp_path / "main.tf")
    for raw in (f'  {target} ', f'"{target}"', f"'{target}'"):
        files, _ = app.resolve_input(raw)
        assert files == [target], raw


def test_missing_path_returns_nothing(tmp_path):
    files, workdir = app.resolve_input(str(tmp_path / "nope.tf"))
    assert files == [] and workdir is None


def test_non_terraform_file_is_rejected(tmp_path):
    target = write(tmp_path / "notes.txt", "hello")
    assert app.resolve_input(str(target))[0] == []


def test_oversized_file_is_rejected(tmp_path):
    target = write(tmp_path / "big.tf", "#" * (app.MAX_FILE_BYTES + 1))
    assert app.resolve_input(str(target))[0] == []


def test_empty_directory_returns_nothing(tmp_path):
    assert app.resolve_input(str(tmp_path))[0] == []


# ---------------------------------------------------------------------------
# zip archives
# ---------------------------------------------------------------------------

def make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as z:
        for name, content in entries.items():
            z.writestr(name, content)
    return path


def test_zip_is_extracted_and_scanned(tmp_path):
    archive = make_zip(tmp_path / "p.zip", {
        "project/main.tf": 'resource "aws_ebs_volume" "v" { size = 1 }',
        "project/modules/db.tf": 'resource "aws_kms_key" "k" {}',
        "project/notes.txt": "ignore me",
    })
    files, workdir = app.resolve_input(str(archive))
    assert sorted(f.name for f in files) == ["db.tf", "main.tf"]
    assert workdir is not None and workdir.exists()


def test_zip_slip_entries_are_refused(tmp_path):
    """A crafted archive must not be able to write outside the temp directory.

    Without the guard, extracting '../../evil.tf' would overwrite a file two
    levels above the extraction root.
    """
    archive = make_zip(tmp_path / "evil.zip", {
        "ok.tf": 'resource "aws_kms_key" "k" {}',
        "../../evil.tf": 'resource "aws_kms_key" "bad" {}',
        "/absolute.tf": 'resource "aws_kms_key" "bad2" {}',
    })
    files, workdir = app.resolve_input(str(archive))
    names = [f.name for f in files]
    assert "evil.tf" not in names
    assert "ok.tf" in names
    assert not (tmp_path.parent.parent / "evil.tf").exists()


def test_zip_without_terraform_returns_nothing(tmp_path):
    archive = make_zip(tmp_path / "empty.zip", {"readme.md": "# hi"})
    files, workdir = app.resolve_input(str(archive))
    assert files == [] and workdir is None


def test_corrupt_zip_is_handled(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"this is not a zip file")
    files, workdir = app.resolve_input(str(archive))
    assert files == [] and workdir is None


def test_oversized_zip_member_is_skipped(tmp_path):
    archive = make_zip(tmp_path / "big.zip", {
        "ok.tf": 'resource "aws_kms_key" "k" {}',
        "huge.tf": "#" * (app.MAX_FILE_BYTES + 1),
    })
    files, _ = app.resolve_input(str(archive))
    assert [f.name for f in files] == ["ok.tf"]
