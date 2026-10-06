import asyncio, json, sys, traceback
from scanner.orchestrator import run
from scanner.models import ScanProfile


ALLOWED_COMMANDS = {
    "headers_scan",
    "tls_scan",
    "tech_scan",
    "assessment_scan",
    "xss_scan",
}


async def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request_id = None
        try:
            request = json.loads(line)
            request_id = request.get("id")
            command = request.get("command")
            target = request.get("target")
            profile = request.get("profile", ScanProfile.PASSIVE.value)

            if not isinstance(command, str) or command not in ALLOWED_COMMANDS:
                raise ValueError("Unsupported scanner command")
            if not isinstance(target, str) or not target.strip():
                raise ValueError("Target is required")
            if not isinstance(profile, str) or profile not in {p.value for p in ScanProfile}:
                raise ValueError("Unsupported scan profile")

            print(
                json.dumps(
                    {
                        "id": request_id,
                        "event": "started",
                        "command": command,
                        "profile": profile,
                    }
                ),
                flush=True,
            )

            def progress(module):
                print(
                    json.dumps(
                        {
                            "id": request_id,
                            "event": "progress",
                            "module": module,
                        }
                    ),
                    flush=True,
                )

            result = await asyncio.wait_for(
                run(command, target.strip(), progress, profile),
                timeout=60,
            )
            print(
                json.dumps(
                    {"id": request_id, "event": "summary", "data": result.get("summary", {})}
                ),
                flush=True,
            )
            print(
                json.dumps({"id": request_id, "event": "result", "data": result}),
                flush=True,
            )
        except asyncio.TimeoutError:
            print(
                json.dumps(
                    {
                        "id": request_id,
                        "event": "error",
                        "error": "Scanner timed out after 60 seconds",
                    }
                ),
                flush=True,
            )
        except Exception as exc:
            print(
                json.dumps(
                    {"id": request_id, "event": "error", "error": str(exc)}
                ),
                flush=True,
            )
            if request_id is None:
                traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
