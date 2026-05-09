"""Wrap docker invocation with Windows path handling. Pass MODE env from arg2."""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
wd = HERE.replace('\\', '/')
mount_host = f'/{wd[0].lower()}{wd[2:]}'

env = os.environ.copy()
env['MSYS_NO_PATHCONV'] = '1'

script = sys.argv[1] if len(sys.argv) > 1 else 'analyze.sage'
extra = sys.argv[2:]
mode_env = []
if extra:
    mode_env = ['-e', f'MODE={extra[0]}']

cmd = ['docker', 'run', '--rm',
       '-v', f'{mount_host}:/work',
       '-w', '/work'] + mode_env + [
       'sage-crypto:latest', 'sage', script]

print('[run]', cmd, file=sys.stderr)
r = subprocess.run(cmd, env=env)
sys.exit(r.returncode)
