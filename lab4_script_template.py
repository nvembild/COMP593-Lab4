
import pandas as pd
import re


def main():
    log_file = get_log_file_path_from_cmd_line()

    regex = r'\bDPT=(\d+)\b'
    filed_logs, caped_data = filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False)
    tally_port_traffic(filed_logs)
    generate_port_traffic_report(log_file, '80')
    generate_port_traffic_report(log_file)
    generate_source_ip_log(log_file, '192.168.5.17')

# TODO: Step 3

def get_log_file_path_from_cmd_line():
    return 'gateway.log'

# TODO: Steps 4-7

def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    logs = []
    caped_data = []
    with open(log_file, 'r') as n:
        for line in n:
            match = re.search(regex, line, re.IGNORECASE if ignore_case else 1)

            if match:
                logs.append(line)
                caped_data.append(match.groups())

    if print_summary:
        print(f"Num of matching records: {len(logs)}")

    if print_records:
        for log in logs:
            print(log)
    return logs, caped_data

# TODO: Step 8

def tally_port_traffic(logs):
    traffic = {}

    for log in logs:
        M = re.search(r'\bDPT=(\d+)\b', log)

        if M:
            port = M.group(1)
            traffic[port] = traffic.get(port, 0) + 1

    return

# TODO: Step 9

def generate_port_traffic_report(log_file, port_number):
    data = []

    with open(log_file, 'r') as n:
        lines = n.readlines()

    for line in lines:
        fields = line.split()

        if fields[5] == port_number:
            date = fields[0]
            time = fields[1]
            source_ip = fields[2]
            destination_ip = fields[3]
            source_port = fields[4]
            destination_port = fields[5]
            port_number = fields[6]
            data.append([date, time, source_ip, destination_ip, source_port, destination_port, port_number])
            

    filename = 'destination_port_%s_report.csv' % port_number
    with open(filename, 'w') as n:
        writer = csv.writer(n)
        writer.writerow(['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
        writer.writerows(data)

    print('Report successfully generated: %s' % filename)
    return

# TODO: Step 11

def invalid_users_report(log_file):
  insidefile = open(log_file, 'r')
  outsidefile = open('invalid_users.csv', 'w')
  outsidefile.write("Date,Time,Username,IP Address\n")
  for line in insidefile:
    fields = line.split(',')
    if fields[3] == "invalid":
      outsidefile.write("{},{},{},{}\n".format(fields[0], fields[1], fields[2], fields[4], fields[5], fields[6]))
  insidefile.close()
  outsidefile.close()

# TODO: Step 12

def generate_source_ip_log(log_file, ip_address):
    df = pd.read_csv(log_file, delimiter='\s+', header=None, index_col=True,
            names=['timestamp', 'host', 'service', 'message'])
    df_src = df[df['message'].str.contains(ip_address)]
    fname = 'source_ip_' + re.sub('\.', '_', ip_address) + '.log'
    df_src.to_csv(fname, index=True, header=True, sep=' ')

    print("File saved as " + fname)
    return

if __name__ == '_main_':
    main()