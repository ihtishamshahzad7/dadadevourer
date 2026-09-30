import asyncio, json, sys, traceback
from headers_scanner import run

async def main():
    for line in sys.stdin:
        line=line.strip()
        if not line: continue
        request_id=None
        try:
            request=json.loads(line); request_id=request.get("id")
            command=request.get("command"); target=request.get("target")
            if not isinstance(command,str) or command not in {"headers_scan","tls_scan","tech_scan","assessment_scan"}: raise ValueError("Unsupported scanner command")
            if not isinstance(target,str) or not target.strip(): raise ValueError("Target is required")
            print(json.dumps({"id":request_id,"event":"started","command":command}),flush=True)
            result=await asyncio.wait_for(run(command,target.strip()),timeout=45)
            print(json.dumps({"id":request_id,"event":"result","data":result}),flush=True)
        except asyncio.TimeoutError:
            print(json.dumps({"id":request_id,"event":"error","error":"Scanner timed out after 45 seconds"}),flush=True)
        except Exception as exc:
            print(json.dumps({"id":request_id,"event":"error","error":str(exc)}),flush=True)
            if request_id is None: traceback.print_exc(file=sys.stderr)

if __name__=="__main__":
    asyncio.run(main())
