#!/usr/bin/env python3
import argparse
import psutil
import time

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=str, help="PID to monitor its termination.")
    parser.add_argument("output", type=str, help="file name to export results.")

    args = parser.parse_args()
    if not args.pid:
        print("PID should be specified.")
        return

    pid = int(args.pid)
    init_time = time.time()
    sys_cpu_usages, user_cpu_usages = [], []
#    with open("cpu.txt", 'w') as fd:
#        while psutil.pid_exists(pid):
#            cpu_usage = psutil.cpu_percent(interval=0.1)
#            timestamp = time.time() - init_time
#            fd.write("{:.3f} {}\n".format(timestamp, cpu_usage))
#            cpu_usages.append(cpu_usage)

    while psutil.pid_exists(pid):
        cpu_usage = psutil.cpu_times_percent(interval=0.1)
        sys_cpu_usages.append(cpu_usage.system)
        user_cpu_usages.append(cpu_usage.user)
#        print("cpu usage: sys: {:.2f} %, user: {:.2f} %".format(cpu_usage.system, cpu_usage.user))

    with open(args.output, 'a') as fd:
        if sys_cpu_usages and user_cpu_usages:
            fd.write("average cpu usage: sys: {:.2f} %, user: {:.2f} %\n".format(sum(sys_cpu_usages) / float(len(sys_cpu_usages)), sum(user_cpu_usages) / float(len(user_cpu_usages))))

if __name__ == "__main__":
    main()
