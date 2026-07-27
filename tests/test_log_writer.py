from app.tools.log_writer import append_log, read_log


def test_append_and_read_log(tmp_path):
    log_path = tmp_path / "hook.log"

    append_log(str(log_path), "line1")
    append_log(str(log_path), "line2\n")

    content = read_log(str(log_path))
    assert content == "line1\nline2\n"
