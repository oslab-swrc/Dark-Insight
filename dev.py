#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot
import numpy
import os
import psutil
import time

DEV_SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

def draw_ferret_graph(data_path, extension='svg'):
    if not data_path:
        return

    labels, exe_times, cpu_usages = [], [], []
    with open(data_path, 'r') as fd:
        for line in fd:
            data = line.split()
            if len(data) == 0 or data[0][:1] == '#':
                continue
            labels.append(data[0])
            exe_times.append(float(data[1]))
            cpu_usages.append(float(data[2]))

    bar_width = 0.6
    index = numpy.arange(len(labels))
    figure, axes = matplotlib.pyplot.subplots()
#    axes.set_title('ferret exe time and cpu usage')
    axes.set_ylabel('execution time (s)')
    axes.set_yticks(numpy.arange(0, max(exe_times), 5))
    axes.set_xlabel("the number of threads (seg-extract-vec-rank)")
    axes.set_xticks(index)
    axes.set_xticklabels(tuple(labels), rotation=90)

    axes.bar(index, exe_times, align='center', width=bar_width, color='lightgray', label='execution time')
    axes.legend(bbox_to_anchor=(0., 1.0, 1., .102), loc=3, borderaxespad=0., framealpha=0)

    twin_ax = axes.twinx()
    twin_ax.set_ylabel('cpu usage (%)', color='black')
    twin_ax.tick_params('y', colors='black')
    twin_ax.set_yticks(numpy.arange(0, 100, 5))
    twin_ax.plot(index, cpu_usages, color='black', marker='x', markersize=5, label='cpu usage')

    twin_ax.legend(bbox_to_anchor=(0, 1.0, 1., 0.102), loc=4, borderaxespad=0., framealpha=0)

    result_path = os.path.join(os.getcwd(), 'figure.' + extension)
    matplotlib.pyplot.savefig(result_path, bbox_inches='tight')

def draw_rocksdb_graph(data_path, data_type='latency', extension='svg'):
    if not data_path:
        return

    thread_counts, latencies, throughputs, = [], [], []
    sys_cpu_usages, user_cpu_usages, exe_times = [], [], []
    patched_thread_counts, patched_latencies, patched_throughputs = [], [], []
    patched_sys_cpu_usages, patched_user_cpu_usages, patched_exe_times = [], [], []
    with open(data_path, 'r') as fd:
        for line in fd:
            data = line.split()
            if len(data) == 0 or data[0][:1] == '#':
                continue
            if data[0] == 'without_patch':
                if len(thread_counts) % 4 == 3:
                    thread_counts.append(int(data[1]))
                else:
                    thread_counts.append(' ')
                latencies.append(float(data[2]))
                throughputs.append(float(data[3]))
                sys_cpu_usages.append(float(data[4]))
                user_cpu_usages.append(float(data[5]))
                exe_times.append(float(data[6]))
            else:
                if len(patched_thread_counts) % 4 == 3:
                    patched_thread_counts.append(int(data[1]))
                else:
                    patched_thread_counts.append(' ')
                patched_latencies.append(float(data[2]))
                patched_throughputs.append(float(data[3]))
                patched_sys_cpu_usages.append(float(data[4]))
                patched_user_cpu_usages.append(float(data[5]))
                patched_exe_times.append(float(data[6]))

    bar_width = 0.4
    index = numpy.arange(len(thread_counts))
    figure, axes = matplotlib.pyplot.subplots()
#    axes.set_title('rocksdb db_stress' + data_type)
    axes.text(0.5, 0.96, 'rocksdb db_stress ' + data_type,
        horizontalalignment="center", transform=axes.transAxes)
    if data_type == 'latency':
        axes.set_ylabel('latency (μs)/op)')
        axes.set_yticks(numpy.arange(0, max(latencies) + 50, 50))
    elif data_type == 'throughput':
        axes.set_ylabel('throughput (ops/sec)')
        axes.set_yticks(numpy.arange(0, max(patched_throughputs) + 2000, 4000))
    else:
        axes.set_ylabel('exe time (sec)')
        axes.set_yticks(numpy.arange(0, max(exe_times) + 100, 200))

    axes.set_xlabel("the number of threads")
    axes.set_xticks(index + bar_width / 2)
    axes.set_xticklabels(tuple(thread_counts))

    if data_type == 'latency':
        axes.bar(index, latencies, align='center', width=bar_width, color='lightgray', label='w/o patch')
        axes.bar(index + bar_width, patched_latencies, align='center', width=bar_width, color='gray', label='w/ patch')
    elif data_type == 'throughput':
        axes.bar(index, throughputs, align='center', width=bar_width, color='lightgray', label='w/o patch')
        axes.bar(index + bar_width, patched_throughputs, align='center', width=bar_width, color='gray', label='w/ patch')
    else:
        axes.bar(index, exe_times, align='center', width=bar_width, color='lightgray', label='w/o patch')
        axes.bar(index + bar_width, patched_exe_times, align='center', width=bar_width, color='gray', label='w/ patch')

    axes.legend(bbox_to_anchor=(0., 1.0, 1., .102), loc=3, borderaxespad=0., framealpha=0)

    twin_ax = axes.twinx()
    twin_ax.set_ylabel('cpu usage (%)', color='blue')
    twin_ax.tick_params('y', colors='blue')
    twin_ax.set_yticks(numpy.arange(0, 100, 5))
    twin_ax.set_ylim([0, 100])
    twin_ax.plot(index + bar_width / 2, sys_cpu_usages, color='red', marker='x', markersize=5, label='sys cpu w/o patch')
    twin_ax.plot(index + bar_width / 2, patched_sys_cpu_usages, color='red', marker='+', markersize=5, label='sys cpu w/ patch')
    twin_ax.plot(index + bar_width / 2, user_cpu_usages, color='blue', marker='x', markersize=5, label='user cpu w/o patch')
    twin_ax.plot(index + bar_width / 2, patched_user_cpu_usages, color='blue', marker='+', markersize=5, label='user cpu w/ patch')

    twin_ax.legend(bbox_to_anchor=(0, 1.0, 1., 0.102), loc=4, ncol=2, borderaxespad=0., framealpha=0)

    result_path = os.path.join(os.getcwd(), data_type + '.' + extension)
    matplotlib.pyplot.savefig(result_path, bbox_inches='tight')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", type=str, help="Available command {draw}.")
    parser.add_argument("command_args", nargs='*', type=str, default='',
        help="supplementaries for commands. e.g., file name.")

    args = parser.parse_args()
    if args.command == 'draw' and len(args.command_args) > 1:
        drawing_target = args.command_args[0]
        filename = args.command_args[-1]
        data_path = os.path.realpath(os.path.join(os.getcwd(), filename))
        if drawing_target == 'ferret':
            draw_ferret_graph(data_path)
        elif drawing_target == 'rocksdb':
            draw_rocksdb_graph(data_path, 'latency')
            draw_rocksdb_graph(data_path, 'throughput')
            draw_rocksdb_graph(data_path, 'exe_time')
        else:
            print("Not supported draw type: {}.".format(drawing_target))
    else:
        print("Wrong command or missing command args. See help with -h")


if __name__ == "__main__":
    main()
