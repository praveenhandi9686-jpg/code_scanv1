"""Runs submitted code and captures its output. NOT a hardened sandbox: the code can read files and use the network.
Enabled only when ENABLE_CODE_EXECUTION=true (default: on only if FLASK_ENV=development)."""
import os, shutil, subprocess, sys, tempfile, time
CMD = {"python": [sys.executable, "-I"], "javascript": ["node"], "bash": ["bash"], "ruby": ["ruby"], "php": ["php"]}
EXT = {"python": ".py", "javascript": ".js", "bash": ".sh", "ruby": ".rb", "php": ".php"}
CAP = 20000

def enabled():
    if os.getenv("VERCEL") or os.getenv("RENDER"): return False   # never run visitor code on a public deployment: it could read the function's secrets
    v = (os.getenv("ENABLE_CODE_EXECUTION") or "").lower()
    return v == "true" or (v == "" and os.getenv("FLASK_ENV") == "development")

def _limits():  # POSIX only: CPU seconds and written file size
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6)); resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 2**20,) * 2)

_s = lambda x: x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")

def run_code(lang, src, timeout=5):
    if lang == "html": return {"kind": "preview"}
    if lang not in CMD: return {"kind": "unsupported", "message": f"Running {lang} is not supported. Python, JavaScript, Bash, Ruby and PHP can be run; HTML shows a live preview."}
    if not enabled(): return {"kind": "disabled", "message": "Running code is disabled on this deployment for security." if (os.getenv("VERCEL") or os.getenv("RENDER")) else "Code execution is turned off. Set ENABLE_CODE_EXECUTION=true in .env to enable it (only on a machine you trust)."}
    cmd = list(CMD[lang])
    if cmd[0] != sys.executable and not shutil.which(cmd[0]): return {"kind": "missing", "message": f"'{cmd[0]}' is not installed on the server."}
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "main" + EXT[lang])
        with open(p, "w", encoding="utf-8") as fh: fh.write(src)
        env = {"PATH": os.environ.get("PATH", ""), "HOME": d, "TMPDIR": d, "TEMP": d, "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "PYTHONIOENCODING": "utf-8"}
        t, timed = time.time(), False
        try:
            r = subprocess.run(cmd + [p], cwd=d, env=env, input="", capture_output=True, timeout=timeout, preexec_fn=_limits if os.name == "posix" else None)
            out, err, code = _s(r.stdout), _s(r.stderr), r.returncode
        except subprocess.TimeoutExpired as e:
            out, err, code, timed = _s(e.stdout), _s(e.stderr), -1, True
        err = err.replace(d, ".")
    return {"kind": "ran", "stdout": out[:CAP], "stderr": err[:CAP], "exit_code": code, "duration_ms": int((time.time() - t) * 1000), "timed_out": timed}
