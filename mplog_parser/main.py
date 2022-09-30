"""MPLog parser main module."""
import argparse
import csv
import fnmatch
import os
import re
import sys
from datetime import datetime, timedelta
from typing import Any, Union

from mplog_parser.adapters.os_adapter import OsAdapter


class MpLogParser:
    """MPLogParser class finds and parses interesting entries and writes results to output files as CSV."""

    def __init__(self, adapter: OsAdapter, mplogs_directory: str, output_directory: str):
        """Creates MpLogParser object from command line arguments.
        Defines mainly:
        - Regexes use to parse entries
        - Regex use to get MPLogs
        - Output file names
        """
        self._mplogs_directory: str = mplogs_directory
        self._output_directory: str = output_directory
        self._os_adapter: OsAdapter = adapter
        self._mini_filter_unsuccessful_scan_status_pattern: str = r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z).*\[Mini-filter\] (Unsuccessful scan status): (.+) (Process): (.+), (Status): (.+), (State): (.+), (ScanRequest) (.+), (FileId): (.+), (Reason): (.+), (IoStatusBlockForNewFile): (.+), (DesiredAccess):(.+), (FileAttributes):(.+), (ScanAttributes):(.+), (AccessStateFlags):(.+), (BackingFileInfo): (.+)"
        self._mini_filter_blocked_file_pattern: str = r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z).*\[Mini-filter\] (Blocked file): (.+) (Process): (.+), (Status): (.+), (State): (.+), (ScanRequest) (.+), (FileId): (.+), (Reason): (.+), (IoStatusBlockForNewFile): (.+), (DesiredAccess):(.+), (FileAttributes):(.+), (ScanAttributes):(.+), (AccessStateFlags):(.+), (BackingFileInfo): (.+)'
        self._exclusion_list_pattern: str = r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z) (\[Exclusion\]) (.+) -> (.+)'
        self._lowfi_pattern: str = r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z).*(lowfi): (.+)"
        self._detection_add_pattern: str = r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z).*(DETECTION_ADD(?:#2)?) (.*)'
        self._threat_command_line_pattern: str = r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z).*(threat): (.+)'
        self._detection_event_pattern: str = r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z).*(DETECTIONEVENT MPSOURCE_SYSTEM) (.*)'
        self._original_filename_pattern: str = r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z).*(original file name) "(.*)" (for) "(.*)", (hr)=(\w*)'
        self._ems_pattern: str = r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z).*(process): (\w*) (pid): (\d*), (sigseq): (\w*), (sendMemoryScanReport): (\d*), (source): (\d*)'
        self._process_image_name_pattern: str = r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z) (ProcessImageName): (.*), (Pid): (\d*), (TotalTime): (\d*), (Count): (\d*), (MaxTime): (\d*), (MaxTimeFile): (.*), (EstimatedImpact): (.*)'
        self._bm_telemetry_pattern: str = r'BEGIN BM telemetry(?:.*\n)+?END BM telemetry'
        self._resource_scan_pattern: str = r'Begin Resource Scan(?:.*\n)+?End Scan'
        self._threat_actions_pattern: str = r'Beginning threat actions(?:.*\n)+?Finished threat actions'
        self._rtp_perf_pattern: str = r'[*]{28}RTP Perf Log[*]{27}(?:.*\n)+?[*]{26}END RTP Perf Log[*]{25}'
        self._mini_filter_unsuccessful_scan_status_output_csv = self._os_adapter.join(
            self._output_directory, 'MPLog_UnsuccessfulScanStatus.csv')
        self._mini_filter_blocked_file_output_csv = self._os_adapter.join(self._output_directory,
                                                                          'MPLog_BlockedFile.csv')
        self._exclusion_list_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_ExclusionList.csv')
        self._lowfi_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_Lowfi.csv')
        self._detection_add_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_DetectionAdd.csv')
        self._threat_command_line_csv_output = self._os_adapter.join(self._output_directory,
                                                                     'MPLog_ThreatCommandLine.csv')
        self._detection_event_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_DetectionEvent.csv')
        self._original_filename_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_OriginalFilename.csv')
        self._ems_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_Ems.csv')
        self._bm_telemetry_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_BMTelemetry.csv')
        self._resource_scan_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_ResourceScan.csv')
        self._threat_action_output_csv = self._os_adapter.join(self._output_directory, 'MPLog_ThreatAction.csv')
        self._process_image_name_csv_output = self._os_adapter.join(self._output_directory,
                                                                    'MPLog_ProcessImageName.csv')
        self._rtp_perf_csv_output = self._os_adapter.join(self._output_directory, 'MPLog_RTPPerf.csv')
        self._entries_parser_regex = re.compile(r'^([\w -]+):(.+)$', re.MULTILINE)
        self.mplog_file_name_pattern = '*MPLog-*'

    EPOCH_AS_FILETIME: int = 116444736000000000  # January 1, 1970 as MS file time
    HUNDREDS_OF_NANOSECONDS: int = 10000000

    def filetime_to_dt(self, ft: int) -> str:
        """Converts a filetime to datetime format."""
        us = (ft - self.EPOCH_AS_FILETIME) // 10
        return (datetime(1970, 1, 1) + timedelta(microseconds=us)).isoformat()

    def write_results(self, output_file: str, rows: list, encoding: str = 'UTF-16') -> None:
        """Writes results to CSV file."""
        if not rows:
            return
        with open(output_file, 'a', newline='', encoding=encoding) as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=rows[0].keys())
            if csv_file.tell() == 0:  # check if file already exists to avoid writing multiple headers.
                writer.writeheader()
            for row in rows:
                try:
                    writer.writerow(row)
                except UnicodeError:
                    return self.write_results(output_file, rows, encoding='UTF-8')

    def rtp_perf_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses RTP perf log entries."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._rtp_perf_pattern, logs):
            entry = dict()
            for hit in re.findall(
                    re.compile(
                        r'(RTP Start):(.*)(Last Perf):(.*)(First RTP Scan):(.*)(Plugin States)'
                        r':(.*)(Process Exclusions):\n(.*)(Path Exclusions):\n(.*)(Ext '
                        r'Exclusions):\n(.*)Worker Threads', re.MULTILINE | re.DOTALL), match):
                entry['rtp_start'] = hit[1].strip('\n')
                entry['last_perf'] = hit[3].strip('\n')
                entry['first_rtp_scan'] = hit[5].strip('\n')
                entry['plugin_states'] = hit[7].strip('\n')
                entry['process_exclusions'] = re.findall(re.compile(r'^\s+(.*)$', re.MULTILINE), hit[9])
                entry['path_exclusions'] = re.findall(re.compile(r'^\s+(.*)$', re.MULTILINE), hit[11])
                entry['extension_exclusions'] = re.findall(re.compile(r'^\s+(.*)$', re.MULTILINE), hit[13])
            results.append(entry)
        return results

    def mini_filter_blocked_file_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parse Mini-Filter blocked file log entries."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._mini_filter_blocked_file_pattern, logs):
            entry = dict()
            entry['timestamp'] = match[0]
            entry['full_path'] = match[2]
            entry['process_name'] = match[4]
            entry['status'] = match[6]
            entry['state'] = match[8]
            entry['scan_request'] = match[10]
            entry['file_id'] = match[12]
            entry['reason'] = match[14]
            entry['io_status_block_for_new_file'] = match[16]
            entry['desiredaccess'] = match[18]
            entry['file_attributes'] = match[20]
            entry['scan_attributes'] = match[22]
            entry['access_state_flags'] = match[24]
            entry['backing_file_info'] = match[26]
            results.append(entry)
        return results

    def mini_filter_unsuccessful_scan_status_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parse Mini-Filter unsucessful scan status log entries."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._mini_filter_unsuccessful_scan_status_pattern, logs):
            entry = dict()
            entry['timestamp'] = match[0]
            entry['full_path'] = match[2]
            entry['process_name'] = match[4]
            entry['status'] = match[6]
            entry['state'] = match[8]
            entry['scan_request'] = match[10]
            entry['file_id'] = match[12]
            entry['reason'] = match[14]
            entry['io_status_block_for_new_file'] = match[16]
            entry['desiredaccess'] = match[18]
            entry['file_attributes'] = match[20]
            entry['scan_attributes'] = match[22]
            entry['access_state_flags'] = match[24]
            entry['backing_file_info'] = match[26]
            results.append(entry)
        return results

    def exclusion_list_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses exclusions lists."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._exclusion_list_pattern, logs):
            entry = dict()
            entry['timestamp'] = match[0]
            entry['full_path_with_drive_letter'] = match[2]
            entry['full_path_with_device_path'] = match[3]
            results.append(entry)
        return results

    def detectionevent_mpsource_system_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses detection events."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._detection_event_pattern, logs):
            entry = dict()
            entry['timestamp'] = match[0]
            entry['command_line'] = match[2]
            results.append(entry)
        return results

    def detection_add_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses detection_add log entries."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._detection_add_pattern, logs):
            entry = dict()
            entry['timestamp'] = match[0]
            entry['command_line'] = match[2]
            results.append(entry)
        return results

    def lowfi_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses Windows Defender Lowfi entries which contain timestamp and command lines."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._lowfi_pattern, logs):
            entry = dict()
            entry['timestamp'] = match[0]
            entry['command_line'] = match[2]
            results.append(entry)
        return results

    def threatcommandline_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses Windows Defender ThreatCommandLine entries which contain timestamp and command line."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._threat_command_line_pattern, logs):
            entry = {'timestamp': match[0], 'command_line': match[2]}
            results.append(entry)
        return results

    def ems_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses EMS scan log entries."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._ems_pattern, logs):
            results.append({
                'timestamp': match[0],
                'process': match[2],
                'pid': match[4],
                'sigseq': match[6],
                'send_memory_scan_report': match[8],
                'source': match[10]
            })
        return results

    def originalfilename_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses original file name change log entries."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._original_filename_pattern, logs):
            results.append({'timestamp': match[0], 'original_filename': match[2], 'full_path': match[4]})
        return results

    def processimagename_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses process image name log entries."""
        results: list[dict[str, Any]] = list()
        for match in re.findall(self._process_image_name_pattern, logs):
            results.append({
                'timestamp': match[0],
                'process_image_name': match[2],
                'pid': match[4],
                'total_time': match[6],
                'count': match[8],
                'max_time': match[10],
                'full_path': match[12],
                'estimated_impact': match[14]
            })
        return results

    def bmtelemetry_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses Behavior Monitoring telemetry log entries."""
        results: list[dict[str, Any]] = list()
        for lines in re.findall(self._bm_telemetry_pattern, logs):
            raw_entry = {e[0]: e[1] for e in re.findall(self._entries_parser_regex, lines)}
            results.append({
                'timestamp': self.filetime_to_dt(int(raw_entry.get('ProcessCreationTime', ''))),
                'guid': raw_entry.get('GUID', ''),
                'process_creation_time': raw_entry.get('ProcessCreationTime', ''),
                'signature_id': raw_entry.get('SignatureID', ''),
                'signature_sha1': raw_entry.get('SigSha', ''),
                'pid': raw_entry.get('ProcessID', ''),
                'session_id': raw_entry.get('SessionID', ''),
                'creation_time': raw_entry.get('CreationTime', ''),
                'image_path': raw_entry.get('ImagePath', ''),
                'taint_info': raw_entry.get('Taint Info', ''),
                'operations': raw_entry.get('Operations', ''),
                'telemetry_name': raw_entry.get('TelemetryName', ''),
                'image_path_hash': raw_entry.get('ImagePathHash', ''),
                'target_filename': raw_entry.get('TargetFileName', '')
            })
        return results

    def resourcescan_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses resource scan log entries."""
        results: list[dict[str, Any]] = list()
        for lines in re.findall(self._resource_scan_pattern, logs):
            raw_entry = {e[0]: e[1] for e in re.findall(self._entries_parser_regex, lines)}
            results.append({
                'scan_id': raw_entry.get('Scan ID', ''),
                'scan_source': raw_entry.get('Scan Source', ''),
                'start_time': raw_entry.get('Start Time', ''),
                'end_time': raw_entry.get('End Time', ''),
                'resource_schema': raw_entry.get('Resource Schema', ''),
                'resource_path': raw_entry.get('Resource Path', ''),
                'result_count': raw_entry.get('Result Count', ''),
                'threat_name': raw_entry.get('Threat Name', ''),
                'id': raw_entry.get('ID', ''),
                'severity': raw_entry.get('Severity', ''),
                'number_of_resources': raw_entry.get('Number of Resources', ''),
                'extended_info_sigseq': raw_entry.get('Extended Info - SigSeq', ''),
                'extended_info_sigsha': raw_entry.get('Extended Info - SigSha', ''),
            })
        return results

    def threatactions_parser(self, logs: str) -> list[dict[str, Union[list[Any], Any]]]:
        """Parses Threat Actions log entries."""
        results: list[dict[str, Any]] = list()
        for lines in re.findall(self._threat_actions_pattern, logs):
            raw_entry = {e[0]: e[1] for e in re.findall(self._entries_parser_regex, lines)}
            results.append({
                'start_time': raw_entry.get('Start time', ''),
                'threat_name': raw_entry.get('Threat Name', ''),
                'threat_id': raw_entry.get('Threat ID', ''),
                'action': raw_entry.get('Action', ''),
                'resource_action_complete': raw_entry.get('Resource action complete', ''),
                'schema': raw_entry.get('Schema', ''),
                'path': raw_entry.get('Path', ''),
                'resource_refcount': raw_entry.get('Resource refcount', ''),
                'result': raw_entry.get('Result', ''),
                'finished_threat_id': raw_entry.get('Finished threat ID', ''),
                'threat_result': raw_entry.get('Threat result', ''),
                'threat_status_flags': raw_entry.get('Threat status flags', ''),
                'threat_effective_removalpolicy': raw_entry.get('Threat Effective RemovalPolicy', ''),
            })
        return results

    def orchestrator(self) -> None:
        """Runs parsers and writes results to output files."""
        for file in self._os_adapter.listdir(self._mplogs_directory):
            if fnmatch.fnmatch(file, self.mplog_file_name_pattern):
                full_path = self._os_adapter.join(self._mplogs_directory, file)
                try:
                    logs = self._os_adapter.read_file(full_path, 'r', 'UTF-16')
                except UnicodeError:
                    logs = self._os_adapter.read_file(full_path, 'r', 'UTF-8')
                self.write_results(self._rtp_perf_csv_output, self.rtp_perf_parser(logs))
                self.write_results(self._exclusion_list_output_csv, self.exclusion_list_parser(logs))
                self.write_results(self._mini_filter_unsuccessful_scan_status_output_csv,
                                   self.mini_filter_unsuccessful_scan_status_parser(logs))
                self.write_results(self._mini_filter_blocked_file_output_csv,
                                   self.mini_filter_blocked_file_parser(logs))
                self.write_results(self._lowfi_output_csv, self.lowfi_parser(logs))
                self.write_results(self._threat_command_line_csv_output, self.threatcommandline_parser(logs))
                self.write_results(self._process_image_name_csv_output, self.processimagename_parser(logs))
                self.write_results(self._detection_event_output_csv, self.detectionevent_mpsource_system_parser(logs))
                self.write_results(self._detection_add_output_csv, self.detection_add_parser(logs))
                self.write_results(self._ems_output_csv, self.ems_parser(logs))
                self.write_results(self._original_filename_output_csv, self.originalfilename_parser(logs))
                self.write_results(self._bm_telemetry_output_csv, self.bmtelemetry_parser(logs))
                self.write_results(self._resource_scan_output_csv, self.resourcescan_parser(logs))
                self.write_results(self._threat_action_output_csv, self.threatactions_parser(logs))


def main() -> None:
    """Entry point, parsing user input and running key functions."""
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-d',
                        '--directory',
                        help='Location of directory containing log files. NB: Admin rights are needed to access '
                             'Windows Defender folder. When specifying a custom directory, file names must be written following *MPLog-* pattern.',
                        required=False,
                        type=str,
                        default='C:\\ProgramData\\Microsoft\\Windows Defender\\Support\\')
    parser.add_argument('-o', '--output', help='Location of output folder.')
    args = parser.parse_args()
    if args.output:
        try:
            os.mkdir(args.output)
        except FileExistsError:
            print('[+] Output path already exists')
        except FileNotFoundError:
            print('[E] Unable to create output directory')
            sys.exit(-1)

        defender = MpLogParser(OsAdapter(), args.directory, args.output)
        print('Parsing MPLogs')
        defender.orchestrator()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
