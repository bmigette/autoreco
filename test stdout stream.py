import shlex
from subprocess import Popen, PIPE, TimeoutExpired, STDOUT
from threading import Timer

import signal

class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
    raise Alarm

def run(cmd, timeout_sec):
    signal.signal(signal.SIGALRM, alarm_handler)
    
    proc = Popen(shlex.split(cmd), stdout=PIPE, stderr=STDOUT, bufsize=1, text=True, universal_newlines=True)
    
    while proc.poll() is None:
        try:
            signal.alarm(timeout_sec)
            outs = proc.stdout.readline()
            print(outs)
            print("-"*20)
            signal.alarm(0)
        except Alarm:
            #proc.kill()
            print("timeout!")
            #outs, errs = proc.communicate()
            

#:: Progress: [958/4989] :: Job [1/1] :: 328 req/sec :: Duration: [0:00:03] :: Errors: 0 :
# import subprocess
# import asyncio
# from asyncio.subprocess import PIPE
# from asyncio import create_subprocess_exec


# async def _read_stream(stream, callback):
#     while True:
#         line = await stream.readline()
#         if line:
#             callback(line)
#         else:
#             break


# async def runa(command, timeout):
#     command = shlex.split(command)
#     process = await create_subprocess_exec(
#         *command, stdout=PIPE, stderr=asyncio.subprocess.STDOUT
#     )

#     await asyncio.wait(
#         [
#             asyncio.create_task(_read_stream(
#                 process.stdout,
#                 lambda x: print(
#                     "STDOUT: {}".format(x.decode("UTF8"))
#                 ),
#             ))
#         ],

#     )

#     # ,
#     #         asyncio.create_task(_read_stream(
#     #             process.stderr,
#     #             lambda x: print(
#     #                 "STDERR: {}".format(x.decode("UTF8"))
#     #             ),
#     #         )),
#     await process.wait()



# async def main(cmd):
#     await runa(cmd, 30)
    


cmd ="gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.229.213:20000"
# loop = asyncio.get_event_loop()
# loop.run_until_complete(main(cmd))
run(cmd, 60)
# https://stackoverflow.com/a/53323746