from pathlib import Path


#Day 5.1 路径与目录练习
print(Path(__file__).resolve().parent)

data_directory=Path(Path(__file__).resolve().parent)/ "day5_data"
data_directory.mkdir(parents=True, exist_ok=True)

log_path=data_directory/"auth.login.log"

print("name:", log_path.name)
print("stem:", log_path.stem)
print("suffix:", log_path.suffix)
print("suffixes:", log_path.suffixes)
print("parent:", log_path.parent)
print("是否为绝对路径:", log_path.is_absolute())



#Day 5.2 写入、追加与逐行读取
path=Path("day5_data/auth.login.log")

with path.open(mode="w",encoding="utf-8",newline='\n') as f:
    f.write("2026-07-30T09:00:00 LOGIN_FAILED ip=10.0.0.1 user=admin\n\nbad log\n")

with path.open(mode="a",encoding="utf-8",newline="\n") as f:
    f.write('2026-07-30T09:01:00 LOGIN_SUCCESS ip=10.0.0.2 user=alice\n2026-07-30T09:02:00 LOGIN_FAILED ip=192.168.1.5 user=rootn\n')


with path.open(mode="r",encoding="utf-8") as f:
    lines=[line.rstrip("\n") for line in f if line.rstrip("\n")]

print(lines)



#Day 5.3 自定义异常和异常传播
class LogReadError(Exception):
    """读取日志失败。"""
    def read_log_lines(path: Path) -> list[str]:
        try:
            with path.open(mode="r",encoding="utf-8") as f:
                lines=[line.rstrip("\n") for line in f if line.rstrip("\n")]

        except FileNotFoundError as exc:
            raise LogReadError(f"日志文件不存在：{path.name}") from exc

        except PermissionError as exc:
            raise LogReadError(f"没有权限读取该日志：{path.name}") from exc

        except UnicodeDecodeError as exc:
            raise LogReadError(f"日志不是有效的 utf-8 文件：{path.name}") from exc

        except OSError as exc:
            raise LogReadError(f"读取文件时发生文件系统错误：{path.name}") from exc

        else:
            print(len(lines))

        finally:
            print("本次读取结束")

        return lines

    paths=[Path("auth_log_path"),Path(data_directory / "missing.log"),Path(data_directory)]
    for path in paths:
        read_log_lines(path)

