#!/usr/bin/env python
#-*- coding:utf-8 -*-
__author__ = 'Pino_HD'
__date__ = '2017.11.24'

import requests
import argparse
import time
import Queue
import threading


class Usage(object):

    def __init__(self):

        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('-u', metavar = 'URL', help = 'The URL for scan, eg: http://www.Pino.com', dest = 'url')
        self.parser.add_argument('-r', metavar = 'Dictionary', help = 'The dictionary to scan, default: /dict/CTF.txt', dest = 'dic', default = 'dict/CTF.txt')
        self.parser.add_argument('-t', metavar = 'Thread Number', help = 'The thread number to scan', dest = 'threadNum', default = 60)
        self.args = self.parser.parse_args()


class Dirscan(object):

    def __init__(self, url, dic, threadNum):

        print '[START] Dirscan starts!'
        self.url = url
        self.dic = dic
        self.threadNum = threadNum
        self._loadHeaders()
        self._loadDic()

    def _loadHeaders(self):

        self.headers = {
            'Accept': '*/*',
            'Referer': self.url,
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; ',
            'Cache-Control': 'no-cache',
        }


    def _loadDic(self):

        self.q = Queue.Queue()
        with open(self.dic) as f:
            for line in f:
                if line[0:2] != '//': #可以在字典中暂时不想用的某一条目前加//进行注释，扫描器会自动跳过该条目
                    self.q.put(line.strip())
        if self.q.qsize() > 0:
            print 'Total Dictionary size is : ' + str(self.q.qsize())
        else:
            print 'Dictionary is null!'
            quit()

    def _scan(self, url, file):

        html_result = 0
        if(url[-1] != '/'):
            scan_url = url + '/' + file
        else:
            scan_url = url + file
        try:
            html_result = requests.get(url = scan_url, headers = self.headers, timeout = 60)
        except requests.exceptions.ConnectionError:
            pass
        finally:
            if html_result != 0:
                if(html_result.status_code == 200):
                    print '['+ str(html_result.status_code) +']' + html_result.url
                    if(html_result.url[-1] != '/' or html_result.url[-1] != '.' or html_result.url[-1] != ''):
                        self._loadSpecial(url, file)

    def _loadSpecial(self, url, file):

        result = []
        result += self._prefixLoad(file)
        result += self._nonPrefixLoad(file)
        for filename in result:
            if(url[-1] != '/'):
                scan_url = url + '/' + filename
            else:
                scan_url = url + filename
            html_result = 0
            try:
                html_result = requests.get(url = scan_url, headers = self.headers, timeout = 60)
            except requests.exceptions.ConnectionError:
                pass
            finally:
                if html_result != 0:
                    if(html_result.status_code == 200):
                        print '['+ str(html_result.status_code) +']' + html_result.url
    
    def _prefixLoad(self, file):

        rules = ['.swp', '.swo', '.swn', '.swl', '.swm']
        result = []
        for rule in rules:
            result.append('.'+file+rule)
        return result
    
    def _nonPrefixLoad(self, file):

        rules = ['.bak', '.bak_Edietplus', '.save', '.back', '~', '.old', '.zip', '.tar.gz', '.7z']
        result = []
        for rule in rules:
            result.append(file+rule)
        return result


    def run(self):

        while not self.q.empty():
            file = self.q.get()
            url = self.url
            self._scan(url, file)


class Start(object):

    def __init__(self):

        self.usage = Usage()

    def start(self):

        self.scan = Dirscan(self.usage.args.url, self.usage.args.dic, self.usage.args.threadNum)
        for i in range(int(self.usage.args.threadNum)):
            t = threading.Thread(target = self.scan.run)
            t.setDaemon(True)
            t.start()

        while True:
            if threading.activeCount() <= 1:
                break
            else:
                try:
                    time.sleep(0.1)
                except KeyboardInterrupt, e:
                    print '\n[Bye] See you later ~ '
                    exit()
                    
        print 'Dirscan end!!'

if __name__ == '__main__':
    
    start = Start()
    start.start()
