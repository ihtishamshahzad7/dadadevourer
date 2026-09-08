import asyncio
import json
import sys
import traceback
from headers_scanner import run


async def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request_id = None
        try:
            request = json.loads(line)
            request_id = request.get("id")
            if request.get("command") != "headers_scan":
                raise ValueError("Unsupported scanner command")
            target = request.get("target")
            if not isinstance(target, str) or not target.strip():
                raise ValueError("Target is required")
            print(json.dumps({"id": request_id, "event": "started"}), flush=True)
            result = await run(target.strip())
            print(json.dumps({"id": request_id, "event": "result", "data": result}), flush=True)
        except Exception as exc:
            print(json.dumps({"id": request_id, "event": "error", "error": str(exc)}), flush=True)
            if request_id is None:
                traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
