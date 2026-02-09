import os
import sys
from typing import List

import litellm.proxy.proxy_cli as proxy_cli


def _has_flag(args: List[str], flag: str) -> bool:
    for item in args:
        if item == flag or item.startswith(flag + "="):
            return True
    return False


def _inject_arg(args: List[str], flag: str, value: str) -> None:
    if value and not _has_flag(args, flag):
        args.extend([flag, value])

def _print_env_if_debug() -> None:
    if os.environ.get("LITELLM_DEBUG_ENV") != "1":
        return
    print("=== LiteLLM Env Dump (debug) ===")
    for key in sorted(os.environ.keys()):
        print(f"{key}={os.environ.get(key)}")
    print("=== End Env Dump ===")
    sys.stdout.flush()


def main() -> None:
    args = list(sys.argv[1:])

    config_path = os.environ.get("LITELLM_CONFIG_PATH")
    port = os.environ.get("LITELLM_PORT")

    if config_path:
        _inject_arg(args, "--config", config_path)
    if port:
        _inject_arg(args, "--port", port)

    _print_env_if_debug()
    proxy_cli.run_server.main(args=args, prog_name="litellm_server")


if __name__ == "__main__":
    main()
