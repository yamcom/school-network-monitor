from click.testing import CliRunner
from network_monitor.cli.commands import cli


def test_cli_check_config():
    runner = CliRunner()
    # Click 全域參數需放在子命令前面傳遞
    result = runner.invoke(cli, ["-c", "config/settings.yaml", "-s", "config/switches.example.yaml", "check-config"])
    assert result.exit_code == 0
    assert "[OK]" in result.output


def test_cli_export_and_backup(tmp_path):
    runner = CliRunner()
    db_file = tmp_path / "test.db"
    settings_file = tmp_path / "settings.yaml"

    settings_file.write_text(f"""
app:
  name: test
capture:
  interface: ""
  enabled: false
database:
  path: "{db_file.as_posix()}"
""")

    runner.invoke(cli, ["-c", str(settings_file), "-s", "", "poll-switches"])
    assert db_file.exists()

    csv_file = tmp_path / "export.csv"
    res_csv = runner.invoke(cli, ["-c", str(settings_file), "-s", "", "export-csv", "-o", str(csv_file)])
    assert res_csv.exit_code == 0
    assert csv_file.exists()

    backup_dir = tmp_path / "backups"
    res_bk = runner.invoke(cli, ["-c", str(settings_file), "-s", "", "db-backup", "-d", str(backup_dir)])
    assert res_bk.exit_code == 0
    backups = list(backup_dir.glob("*.db"))
    assert len(backups) == 1