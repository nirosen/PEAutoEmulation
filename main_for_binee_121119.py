# from multiprocessing import Process, Manager, cpu_count, Pool, freeze_support
import multiprocessing
import subprocess
from shlex import split
import os
import datetime
import time
from io import StringIO
import traceback
import json
import sys
import argparse
import itertools
import logging

## GLOBALS
# the binee dir is the only one mounted inside the docker
binee_dir_path = "/media/john/DOG_114/mal/binee"
# the binaries dir must be inside the binee_dir_path (so it will be seen by the docker)
# and be specified in the docker command
binaries_dir = "tests"
# the output dir can be anywhere accecible by the python code
output_dir_path = "/home/john/Desktop/output_65K"
# the number of samples to emulate (default 0 unlimited)
limit = 0
timeout_binee = 1
timeout_docker = timeout_binee + 1




def run_binee_docker(dict_manager, binary_name):
    #info('function f')
    #print('hello', name, "-time:", datetime.datetime.now())
    command_line = "docker run -v " + \
                   binee_dir_path + \
                   ":/bineedev/go/src/github.com/carbonblack/binee --rm binee  timeout " + \
                   str(timeout_binee) + \
                   " ./binee " + binaries_dir + "/" + \
                   binary_name
    args = split(command_line)
    timeout_caught = 0
    stdout = ''
    stderr = ''
    returncode = 0

    starttime = time.time()
    try:
        # CompletedProcess returned
        proc = subprocess.run(args,
                              # universal_newlines=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              check=True,
                              timeout=timeout_docker)  # capture_output=True
        stdout = proc.stdout
        stderr = proc.stderr

    # case of docker process timeout (timeout_docker)
    except subprocess.TimeoutExpired as timeouterror:
        stdout = timeouterror.stdout
        stderr = timeouterror.stderr
        timeout_caught = timeouterror.timeout

    # case of docker-process non-zero return code
    except subprocess.CalledProcessError as suberror:
        stdout = suberror.stdout
        returncode = suberror.returncode
        stderr = suberror.stderr
        # add_code = "return code: " + str(suberror.returncode) + " \n\n stderr: \n"
        # stderr = b"".join([str.encode(add_code), suberror.stderr])

    # case of some other docker-process exception that needed to be added in the future
    except:
        with StringIO() as trace:
            traceback.print_exc(file=trace)
            stderr = b"".join(
                [str.encode("**** UNHANDLED EXCEPTION *****\n traceback.print_exc:\n" + trace.getvalue())])

    runtime = time.time() - starttime
    # output stdout to name.syscalls file
    output_file_path = os.path.join(output_dir_path, binary_name + ".syscalls")
    with open(output_file_path, 'wb') as output_file:
        output_file.write(stdout)

    # check how many rows in stdout (syscalls seq length)
    seq_len = stdout.count(b'\n')

    # return stderror and timeout (0 is the default, else what was passed as parameter and timeouted)

    dict_manager[binary_name] = {'seq_len': str(seq_len),
                          'runtime': str(runtime),
                          'timeout_caught': str(timeout_caught),
                          'returncode': str(returncode),
                          'stderr': stderr.decode("utf-8", "replace")}


def get_args():
    # declare use of global vars defined above
    global binee_dir_path
    global binaries_dir
    global output_dir_path
    global limit
    global timeout_binee
    global timeout_docker

    parser = argparse.ArgumentParser()
    parser.add_argument("--binee_dir_path", help="the binee dir is the only one mounted inside the docker",
                        action="store", default=binee_dir_path)
    parser.add_argument("--binaries_dir",
                        help="the binaries dir must be inside the binee_dir_path (so it will be seen by the docker)",
                        action="store", default=binaries_dir)
    parser.add_argument("--output_dir_path_Path", help="the output dir can be anywhere accecible by the python code",
                        action="store", default=output_dir_path)
    parser.add_argument("--limit", type=int, help="the number of samples to emulate (default None unlimited)",
                        action="store", default=None)
    parser.add_argument("--timeout_binee", type=int, help="the time in seconds to limit the process emulation (binee)",
                        action="store", default=timeout_binee)
    parser.add_argument("--timeout_docker", type=int, help="the time in seconds to limit the docker after the timeout of the emulation (binee) reached",
                        action="store", default=timeout_docker)
    args = parser.parse_args()

    # change global vars to user's input
    binee_dir_path = args.binee_dir_path
    binaries_dir = args.binaries_dir
    output_dir_path = args.output_dir_path
    limit = args.limit
    timeout_binee = args.timeout_binee
    timeout_docker = args.timeout_docker

    return args


if __name__ == '__main__':
    args = get_args()
    if not os.path.exists(output_dir_path):
        os.makedirs(output_dir_path)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(output_dir_path, "log.txt")),
            logging.StreamHandler(sys.stdout)
        ])
    logger = logging.getLogger()
    logger.info("main func start, print arguments for this run:")
    logger.info(args.__str__())

    with multiprocessing.Manager() as manager:
        dict_manager = manager.dict()

        cpu_cores = 1
        if sys.platform == 'linux':
            # check avail cpu cores - only-Linux!
            cpu_cores = len(os.sched_getaffinity(0))
        else:
            # check CPU cores number - multi-platform
            cpu_cores = multiprocessing.cpu_count()

        starttime = time.time()
        num_processes = cpu_cores
        multiprocessing.freeze_support()
        with multiprocessing.Pool(num_processes) as pool:
            try:
                map_func = pool.apply_async
                a_results = [map_func(func=run_binee_docker, args=(dict_manager, binary_name))
                             for binary_name in
                             itertools.islice(os.listdir(os.path.join(binee_dir_path, binaries_dir)), 0, limit)]
                # output of func f is none
                # a_output = [p.get() for p in a_results]
                # print(a_output)
                pool.close()
                pool.join()
            except:
                logger.info("---- main loop error ----")
                logger.info(sys.exc_info)
                # output stdout to test.syscalls file
                # print(dict_manager.copy())
                sys.exit(1)
                # dict_manager_file_path = os.path.join(output_dir_path_Path, "errors.json")
                # with open(dict_manager_file_path, 'w') as output_file:
                #     json_dict = json.dumps(dict_manager.copy(), ensure_ascii=False)
                #     output_file.write(json_dict)  # .encode("utf-16"))

        logger.info('That took {} seconds'.format(time.time() - starttime))

        # output stdout to test.syscalls file
        # print(dict_manager.copy())
        dict_manager_file_path = os.path.join(output_dir_path, "errors.json")
        with open(dict_manager_file_path, 'w') as output_file:
            json_dict = json.dumps(dict_manager.copy(), ensure_ascii=False)
            output_file.write(json_dict)  # .encode("utf-16"))

        logger.info("finished run, errors dict in: " + dict_manager_file_path)
