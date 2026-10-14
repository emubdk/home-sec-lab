from homelab.shipper import event_id, read_new_lines


def test_reads_only_complete_new_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("line one\nline two\npartial")
    lines, offset = read_new_lines(log, 0)
    assert [text for _, text in lines] == ["line one\n", "line two\n"]

    with log.open("a") as fh:
        fh.write(" now complete\n")
    lines, offset = read_new_lines(log, offset)
    assert [text for _, text in lines] == ["partial now complete\n"]


def test_truncated_file_is_read_from_start(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("a\nb\n")
    _, offset = read_new_lines(log, 0)
    log.write_text("c\n")
    lines, _ = read_new_lines(log, offset)
    assert [text for _, text in lines] == ["c\n"]


def test_missing_file(tmp_path):
    assert read_new_lines(tmp_path / "nope.log", 0) == ([], 0)


def test_event_id_depends_on_path_and_offset(tmp_path):
    assert event_id(tmp_path / "a", 0) != event_id(tmp_path / "a", 10)
    assert event_id(tmp_path / "a", 0) == event_id(tmp_path / "a", 0)
