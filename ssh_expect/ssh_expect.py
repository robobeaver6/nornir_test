import threading
import paramiko
import re
from time import sleep
import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

fh = logging.FileHandler(r'./log/add_api.log')
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)

class SshExpect:
    shell = None
    sftp = None
    client = None
    transport = None



    # connection = None

    def __init__(self, task):
        logger.info(f'Create SSH Connection Object for {task.host.hostname}')
        self.nos = task.host.platform
        self.hostname = task.host.hostname
        self.port = task.host.port if task.host.port is not None else 22
        self.username = task.host.username
        self.password = task.host.password
        self.config_file = task.nornir.config.ssh.config_file
        self.client = paramiko.client.SSHClient()
        self.conf = self._load_config()
        self.client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        self.client.connect(self.hostname, username=self.username, password=self.password, look_for_keys=False)
        self.transport = paramiko.Transport((self.hostname, self.port))
        self.transport.connect(username=self.username, password=self.password)
        self.base_prompt = None
        self.re_prompt = None

        # thread = threading.Thread(target=self.process)
        # thread.daemon = True
        # thread.start()

    def _load_config(self):
        if self.config_file:
            if os.path.exists('ssh_config'):
                conf = paramiko.SSHConfig()
                with open('ssh_config', 'r') as f:
                    conf.parse(f)
                host_config = conf.lookup(self.hostname)
                if 'proxycommand' in host_config:
                    proxy = paramiko.ProxyCommand(host_config['proxycommand'])
                return conf

    def _setup_terminal(self):
        if self.nos == 'junos':
            self.send_shell('set cli screen-width 0')

    def close_connection(self):
        logger.debug(f'Close SSH Connection for {self.hostname}')
        if self.client is None:
            self.client.close()
            self.transport.close()

    def open_shell(self):
        logger.debug(f'Open SSH Shell for {self.hostname}')
        self.shell = self.client.invoke_shell()
        self.get_prompt()
        self._setup_terminal()

    def close_shell(self):
        logger.debug(f'Close SSH Shell for {self.hostname}')
        self.shell.close()

    def open_sftp(self):
        logger.debug(f'open SFTP Session for {self.hostname}')
        self.sftp = self.client.open_sftp()

    def close_sftp(self):
        logger.debug(f'Close SFTP Session for {self.hostname}')
        self.sftp.close()

    def _get_data(self):
        if self.shell is not None and self.shell.recv_ready():
            data = self.shell.recv(1024).decode('utf-8')
            while self.shell.recv_ready():
                data += self.shell.recv(1024).decode('utf-8')
            return self.strip_ansi_escape_codes(data)
        return ''

    def send_shell(self, command):
        logger.debug(f'Send Command to {self.hostname}: {command}')
        if self.shell:
            self.shell.send(command + "\n")
        else:
            print("Shell not opened.")

    def send_sftp(self, path: str, contents: str):
        logger.debug(f'Send file to {self.hostname}: {path}')
        if self.sftp:
            file_key = self.sftp.file(path, "w", -1)
            file_key.write(contents)
            file_key.flush()
            return f'File Copied: {path}\n'

    def get_prompt(self):
        alldata = ''
        for counter in range(1, 5):
            alldata += self._get_data()
            sleep(1)
        self.base_prompt = re.sub('[#>$\n\r ]', '', alldata.split('\n')[-1])
        self.re_prompt = f'{self.base_prompt}[\#\>\$]'
        # print(f'Base Prompt   = "{self.base_prompt}"')
        # print(f'Proimpt RegEx = "{self.re_prompt}"')

    def expect(self, expect):
        logger.debug(f'Expecting Response on {self.hostname}: {expect}')
        alldata = ''
        expect = self.base_prompt if expect is None else expect
        for counter in range(0, 10):
            alldata += self._get_data()
            if re.search(expect, alldata):
                return alldata
            sleep(1)
        raise RuntimeError(f'Expect string not found: {expect} in \n\n{alldata}')

    def commands_expects(self, commands, expects):
        assert isinstance(commands, list)
        assert isinstance(expects, list)
        # Lists should be the same length, if not, look for the prompt
        output = ''
        while len(commands) > len(expects):
            expects.append(self.base_prompt)
        for command, expect in zip(commands, expects):
            self.send_shell(command)
            output += self.expect(expect)
        return output

    def strip_ansi_escape_codes(self, string_buffer):
        """
        Remove any ANSI (VT100) ESC codes from the output

        http://en.wikipedia.org/wiki/ANSI_escape_code

        Note: this does not capture ALL possible ANSI Escape Codes only the ones
        I have encountered

        Current codes that are filtered:
        ESC = '\x1b' or chr(27)
        ESC = is the escape character [^ in hex ('\x1b')
        ESC[24;27H   Position cursor
        ESC[?25h     Show the cursor
        ESC[E        Next line (HP does ESC-E)
        ESC[K        Erase line from cursor to the end of line
        ESC[2K       Erase entire line
        ESC[1;24r    Enable scrolling from start to row end
        ESC[?6l      Reset mode screen with options 640 x 200 monochrome (graphics)
        ESC[?7l      Disable line wrapping
        ESC[2J       Code erase display
        ESC[00;32m   Color Green (30 to 37 are different colors) more general pattern is
                     ESC[\d\d;\d\dm and ESC[\d\d;\d\d;\d\dm
        ESC[6n       Get cursor position

        HP ProCurve and Cisco SG300 require this (possible others).

        :param string_buffer: The string to be processed to remove ANSI escape codes
        :type string_buffer: str
        """  # noqa
        # log.debug("In strip_ansi_escape_codes")
        # log.debug("repr = {}".format(repr(string_buffer)))

        code_position_cursor = chr(27) + r'\[\d+;\d+H'
        code_show_cursor = chr(27) + r'\[\?25h'
        code_next_line = chr(27) + r'E'
        code_erase_line_end = chr(27) + r'\[K'
        code_erase_line = chr(27) + r'\[2K'
        code_erase_start_line = chr(27) + r'\[K'
        code_enable_scroll = chr(27) + r'\[\d+;\d+r'
        code_form_feed = chr(27) + r'\[1L'
        code_carriage_return = chr(27) + r'\[1M'
        code_disable_line_wrapping = chr(27) + r'\[\?7l'
        code_reset_mode_screen_options = chr(27) + r'\[\?\d+l'
        code_reset_graphics_mode = chr(27) + r'\[00m'
        code_erase_display = chr(27) + r'\[2J'
        code_graphics_mode = chr(27) + r'\[\d\d;\d\dm'
        code_graphics_mode2 = chr(27) + r'\[\d\d;\d\d;\d\dm'
        code_get_cursor_position = chr(27) + r'\[6n'
        code_cursor_position = chr(27) + r'\[m'
        code_erase_display = chr(27) + r'\[J'

        code_set = [code_position_cursor, code_show_cursor, code_erase_line, code_enable_scroll,
                    code_erase_start_line, code_form_feed, code_carriage_return,
                    code_disable_line_wrapping, code_erase_line_end,
                    code_reset_mode_screen_options, code_reset_graphics_mode, code_erase_display,
                    code_graphics_mode, code_graphics_mode2, code_get_cursor_position,
                    code_cursor_position, code_erase_display]

        output = string_buffer
        for ansi_esc_code in code_set:
            output = re.sub(ansi_esc_code, '', output)

        # CODE_NEXT_LINE must substitute with return
        output = re.sub(code_next_line, '\n', output)

        # log.debug("new_output = {0}".format(output))
        # log.debug("repr = {0}".format(repr(output)))

        return output


def main():
    ssh_username = "admin"
    ssh_password = "Admin1"
    ssh_server = "192.168.1.39"
    commands = ['request security pki ca-certificate load ca-profile test filename /var/tmp/test-ca.crt',
                'yes',
                'show security pki ca-certificate',
                'clear security pki ca-certificate all',
                ]
    expects = ['\[yes,no\] \(no\)',
               ]

    connection = SshExpect(ssh_server, ssh_username, ssh_password)
    connection.open_shell()
    output = connection.commands_expects(commands, expects)
    connection.close_connection()
    print(output)


if __name__ == '__main__':
    main()
