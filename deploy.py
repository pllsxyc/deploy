#!/usr/bin/env python3.6
'''
maintainer pllsxyc<pllsxyc@163.com>
repository url: https://github.com/pllsxyc/deploy
'''

'''
此脚本的功能：
主要就是模仿Jenkins参数化构建过程。
1、显示发布选项，一共有 deploy rollback两种
2、呈现现有的tag，倒序排序
'''

import paramiko
import git
import yaml
import argparse
import socket
import sys
import os
import shutil
import threading
import time
import datetime
import zipfile
import tarfile
from paramiko import ssh_exception

SSH_PING_RES = True


def get_items(input_dict):
    output_dict = {}
    if not isinstance(input_dict, dict):
        return output_dict

    def _item(_dict):
        for k, v in _dict.items():
            output_dict[k] = v
            if isinstance(v, dict):
                _item(_dict=v)

    _item(input_dict)
    return output_dict


class SSHException(ssh_exception.AuthenticationException, socket.timeout):
    pass


class SSHInit(object):
    def __init__(self, username, hostname, key_filename, timeout):
        self.username = username
        self.hostname = hostname
        self.key_filename = key_filename
        self.timeout = timeout


class SSHConnect(SSHInit):
    def __enter__(self):
        self.myclient = paramiko.SSHClient()
        self.myclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privatekey = os.path.expanduser(self.key_filename)
        pkey = paramiko.RSAKey.from_private_key_file(privatekey)
        try:
            self.myclient.connect(
                username=self.username,
                hostname=self.hostname,
                # key_filename=self.key_filename,
                pkey=pkey,
                timeout=self.timeout
            )
        except Exception as e:
            print("\033[31m主机  %s  ssh连接失败!!!\033[0m" % self.hostname.strip(), " " * 10, e)
            return False
        else:
            print("\033[32m主机  %s  ssh连接成功!!!\033[0m" % self.hostname.strip())
            return self.myclient

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.myclient.close()


class SshPing(threading.Thread, SSHInit):
    def __init__(self, lock, username, hostname, key_filename, timeout):  #
        super(SshPing, self).__init__()
        SSHInit.__init__(self, username=username, hostname=hostname, key_filename=key_filename, timeout=timeout)
        self.lock = lock

    def run(self):
        with SSHConnect(
                username=self.username,
                hostname=self.hostname,
                key_filename=self.key_filename,
                timeout=self.timeout
        ) as ssh:
            if not ssh:
                with self.lock:
                    global SSH_PING_RES
                    SSH_PING_RES = False


class DeployThread(threading.Thread, SSHInit):
    def __init__(self, username, hostname, key_filename, timeout, remote_commands):
        super(DeployThread, self).__init__()
        SSHInit.__init__(self, username=username, hostname=hostname, key_filename=key_filename, timeout=timeout)
        self.remote_commands = remote_commands
        pass

    def run(self):
        with SSHConnect(
                username=self.username,
                hostname=self.hostname,
                key_filename=self.key_filename,
                timeout=self.timeout
        ) as ssh:
            for cmd in self.remote_commands:
                print("\033[33m===={cmd}\033[0m".format(cmd=cmd))
                ssh.exec_command(cmd)


class TransFile(SSHInit):
    def __init__(self, username, hostname, key_filename, timeout, local_file=None, remote_file=None):
        super(TransFile, self).__init__(username=username, hostname=hostname, key_filename=key_filename,
                                        timeout=timeout)
        self._local_file = local_file
        self._remote_file = remote_file
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.hostname, 22))
        self._trans = paramiko.Transport(self._sock)

        privatekey = os.path.expanduser(self.key_filename)
        pkey = paramiko.RSAKey.from_private_key_file(privatekey)
        self._trans.connect(
            username=self.username,
            pkey=pkey
        )
        self._sftp = paramiko.SFTPClient.from_transport(self._trans)

    def put(self):
        #  Copy localfile to remotefile, overwriting or creating as needed.
        print("==", self._local_file)
        self._sftp.put(self._local_file, self._remote_file)

    # def _put(self, localfile, remotefile):
    #     #  Copy localfile to remotefile, overwriting or creating as needed.
    #     print("==", localfile)
    #     self._sftp.put(localfile, remotefile)

    # def put_all(self):
    #     #  recursively upload a full directory
    #     os.chdir(os.path.split(self._local_path)[0])
    #     parent = os.path.split(self._local_path)[1]
    #     for walker in os.walk(parent):
    #         try:
    #             self._sftp.mkdir(os.path.join(self._remote_path, walker[0]))
    #         except:
    #             pass
    #         for file in walker[2]:
    #             self._put(os.path.join(walker[0], file), os.path.join(self._remote_path, walker[0], file))

    def __enter__(self):
        return self._sftp

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._sftp.close()


class TransFileThread(threading.Thread):
    def __init__(self, local_file, remote_file, username, hostname, key_filename, timeout):
        super(TransFileThread, self).__init__()
        self._username = username
        self._hostname = hostname
        self._key_filename = key_filename
        self._timeout = timeout
        self._local_file = local_file
        self._remote_file = remote_file

    def run(self):
        TransFile(
            username=self._username,
            hostname=self._hostname,
            key_filename=self._key_filename,
            timeout=self._timeout,
            local_file=self._local_file,
            remote_file=self._remote_file
        ).put()


class Deploy():
    def __init__(self, ci_info_yml, git_info_yml, hostlist):
        self._ci_info_yml = ci_info_yml
        self._git_info_yml = git_info_yml
        self._hostlist_file = hostlist

        ci_info_kv = get_items(input_dict=self.get_ci_info())
        git_info_kv = get_items(input_dict=self.get_git_info())
        self.__dict__.update(ci_info_kv)
        self.__dict__.update(git_info_kv)
        # print(self.__dict__)

        # ci info
        self._repo_dir = '/'.join((self.workspace, self.repo_name))
        self.hostlist = list(self.get_hostlist())
        self.tmp_repo_name = "tmp@" + self.repo_name

        print("\033[33m测试主机状态ing。。。。\033[0m")
        self.ssh_ping()
        self.show_tags()

    def ssh_ping(self):
        '''测试是否能成功ssh登陆到对方主机'''

        lock = threading.Lock()
        t_list = []
        for user, _, ip in self.hostlist:
            t = SshPing(
                lock=lock,
                username=user,
                hostname=ip,
                key_filename=self.ssh_secret_filename,
                timeout=self.ssh_timeout
            )
            t.start()
            t_list.append(t)

        for t in t_list: t.join()
        if not SSH_PING_RES:
            print("\033[31m主机ssh连接失败,请检查主机情况，发布退出!!!\033[0m")
            sys.exit(-1)

    def get_ci_info(self):
        '''参数化构建的参数'''
        ci_info = yaml.safe_load(open(self._ci_info_yml))
        # print(ci_info)
        return ci_info

    def get_git_info(self):
        '''参数化git的参数'''
        git_info = yaml.safe_load(open(self._git_info_yml))
        return git_info

    def get_hostlist(self):
        '''参数化主机列表'''
        with open(self._hostlist_file) as fp:
            for host_info in fp.readlines():
                if not host_info.startswith('#'):
                    yield host_info.split(':')

    def show_tags(self):
        def _clone():
            try:
                shutil.rmtree(self._repo_dir)
            except FileNotFoundError:
                pass
            return git.Repo.clone_from(url=self.repo_url, to_path=self._repo_dir)

        if self.delete_workspace_before_build:
            repo = _clone()
        else:
            if not os.path.isdir(self._repo_dir + "/.git"):  # 这里只能检查到是否有.git目录判断是否为一个仓库
                repo = _clone()
            else:
                repo = git.Repo(path=self._repo_dir)
                repo.git.pull()
        print("\033[31mlatest tags:\n\033[0m")
        # 所有的tag
        repo_all_tags = [str(tag) for tag in repo.tags]
        # 环境的tag
        v_tags = list(filter(lambda x: x.startswith(self.tag_startswith), repo_all_tags))
        # 需要打印的tag
        self.tag_list = [tag for tag in v_tags[::-1]] \
            if self.show_tags_number == -1 \
            else [tag for tag in v_tags[-1:(self.show_tags_number + 1) * -1:-1]]
        # 如果没有tag，则显示分支
        if not self.tag_list:
            self.tag_list = [str(tag) for tag in list(repo.branches)[::-1]] \
                if self.show_tags_number == -1 \
                else [str(tag) for tag in list(repo.branches)[-1:(self.show_tags_number + 1) * -1:-1]]

        for tag in self.tag_list: print("\033[33m\t\t%s\033[0m" % str(tag))

    def deploy(self, deploy_action, current_tag):
        '''发布主方法'''
        self.current_tag = current_tag
        ###########记录发布日志###############
        message_list = [time.strftime("%Y%m%d%H%M%S",time.localtime()),"deploy" if deploy_action == "1" else "rollback",current_tag+'\n']
        with open('./.deploy_log','a') as fp:
            fp.write('---'.join(message_list))
        ###########记录发布日志###############

        def _formated_remote_cmd(deploy_action):
            remote_cmds = self.remote_deploy_commands if deploy_action == "1" else self.remote_rollback_commands
            for cmd in remote_cmds:
                yield cmd.format(**self.__dict__)

        # for cmd in _formated_remote_cmd(deploy_action):
        #     print(cmd)
        if deploy_action == "1":
            # 先将仓库拷贝一份，命名为仓库年月日时分秒，发布完成之后将其删除。
            tmp_workspace = '/'.join((self.workspace, self.tmp_repo_name))
            # print(tmp_workspace)
            if os.path.isdir(tmp_workspace): shutil.rmtree(tmp_workspace)
            shutil.copytree(src=self._repo_dir, dst=tmp_workspace)
            repo = git.Repo(path=tmp_workspace)

            repo.git.checkout(current_tag)
            ############执行本地命令########
            print("\033[33m执行本地命令ing。。。。\033[0m")
            os.chdir(tmp_workspace)
            tarfile_name = "{project_name}{current_tag}.tgz".format(project_name=self.project_name,
                                                                    current_tag=current_tag)
            self.local_commands.append("tar czvf {tarfile_name} .[!.]* *".format(tarfile_name=tarfile_name))
            l_cmd = " && ".join(self.local_commands)
            # print(l_cmd)
            os.system(l_cmd)
            ############执行本地命令########

            ########上传代码###########
            print("\033[33m上传代码ing。。。。\033[0m")
            trans_t_list = []
            for user, _, ip in self.hostlist:
                t = TransFileThread(
                    username=user,
                    hostname=ip,
                    key_filename=self.ssh_secret_filename,
                    timeout=self.ssh_timeout,
                    local_file=tarfile_name,
                    remote_file="/tmp/" + tarfile_name
                )
                t.start()
                trans_t_list.append(t)
            for t in trans_t_list: t.join()
            ########上传代码###########
            shutil.rmtree(tmp_workspace)

        ########发布，执行远程命令###########
        print("\033[33m执行远程命令ing。。。。\033[0m")
        t_list = []
        for user, _, ip in self.hostlist:
            t = DeployThread(
                username=user,
                hostname=ip,
                key_filename=self.ssh_secret_filename,
                timeout=self.ssh_timeout,
                remote_commands=_formated_remote_cmd(deploy_action)
            )
            t.start()
            t_list.append(t)
        for t in t_list: t.join()
        ########发布，执行远程命令###########


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', type=str, help='指定主机列表，默认是当前目录下的hostlist')
    parser.add_argument('-g', type=str, help='指定git参数文件，默认是当前目录下的git_info.yml')
    parser.add_argument('-c', type=str, help='指定构建参数文件，默认是当前目录下的ci_info.yml')
    args = parser.parse_args()

    # stopword = ":q"

    d = Deploy(
        hostlist=args.i if args.i else "./hostlist",
        git_info_yml=args.g if args.g else "./git_info.yml",
        ci_info_yml=args.c if args.c else "./ci_info.yml",
    )

    deploy_action = input("\033[31m请输入发布动作:\033[0m\n1) deploy\n2) rollback\n")
    if deploy_action not in ['1', '2']:
        print("\033[31m输入错误！！！\n\033[0m")
        sys.exit(-1)

    current_tag = input("\033[31m请输入tag:\033[0m\n")
    # print(current_tag)
    d.deploy(deploy_action=deploy_action, current_tag=current_tag)


#
if __name__ == "__main__":
    main()

