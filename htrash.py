#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import threading
import socket
import ssl
import os
from urllib import parse
from urllib.parse import urlencode, quote_plus


class MainCLS(object):


    def __init__(self):

        print('+ WAF fuzzing attack testing')

        url       = None
        paramName = None

        # Get the URL
        while(True):
            url = input('URL        : ').strip()
            if(url):
                break

        # Get the param name
        while(True):
            paramName = input('Param name : ').strip()
            if(paramName):
                break

        if(not os.path.isfile('./dictionary.txt')):
            return print('! ./dictionary.txt is not found')

        # Clean out log file
        outFileHandler = open('./out.log', 'wt')
        outFileHandler.write('')
        outFileHandler.close()

        print('+ Loading dictionary ...')

        with open('./dictionary.txt', 'rt') as lines:
            for line in lines:
                self.testPayload(url, paramName, line.strip())


    def saveResult(self, payload, httpStatus, httpMethod, responseLength):

        outFileHandler = open('./out.log', 'at')
        outFileHandler.write('[' + str(httpMethod) + ':' + str(httpStatus) + ':' + str(responseLength) + '] ' + str(payload).strip() + '\n')
        outFileHandler.close()


    def testPayload(self, url, paramName, payload):

        # Test HTTP/GET
        urlParsed = parse.urlparse(url)
        urlParsed = urlParsed._replace(
            query = (
                # Current query
                str(urlParsed.query) +

                # Append separator
                ('&' if urlParsed.query else '') +

                # New query
                urlencode({paramName : payload}, quote_via=quote_plus)
            )
        )

        print(' -> HTTP/GET ...')
        print('    - Request URL     : ' + urlParsed.geturl())
        result = self.httpRequest(url=urlParsed.geturl())
        print('    - Response status : ' + str(result['status-code']))
        print('    - Response length : ' + str(len(result['response-content'])) + ' bytes.')
        self.saveResult(
            payload=payload,
            httpStatus=result['status-code'],
            httpMethod='GET',
            responseLength=len(result['response-content'])
        )

        # Test HTTP/POST
        print(' -> HTTP/POST ...')
        print('    - Request URL     : ' + url)
        result = self.httpRequest(url=url, postData={ paramName: payload })
        print('    - Response status : ' + str(result['status-code']))
        print('    - Response length : ' + str(len(result['response-content'])) + ' bytes.')
        self.saveResult(
            payload=payload,
            httpStatus=result['status-code'],
            httpMethod='POST',
            responseLength=len(result['response-content'])
        )


    def httpRequest(self, url, customHeaders=None, postData=None):

        if(customHeaders):
            # Une las cabeceras personalizadas
            headers.update(customHeaders)

        self.lastUrl = url

        #Formatea la dirección URL
        urlParsed = parse.urlparse(url)
        urlData = {
            'original' : url,
            'path'     : urlParsed.path,
            'query'    : ('?' + urlParsed.query) if urlParsed.query else '',
            'host'     : urlParsed.netloc,
            'port'     : urlParsed.port,
            'scheme'   : urlParsed.scheme
        }

        if urlData['path'] == '':
            urlData['path'] = '/'

        if(not urlData['port']):
            urlData['port'] = 443 if (urlData['scheme'] == 'https') else 80

        # Contenido del envío HTTP
        if(postData):
            packet = '\r\n'.join([
                'POST ' + str(urlData['path'].strip()) + str(urlData['query'].strip()) + ' HTTP/1.1',
                'Host: ' + urlData['host'],
                'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/54.0',
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Content-Length: ' + str(len(urlencode(postData, quote_via=quote_plus))),
                'Content-Type: application/x-www-form-urlencoded',
                'Accept-Language: en-US',
                'Connection: close',
                '',
                urlencode(postData, quote_via=quote_plus)
            ])

        else:
            packet = '\r\n'.join([
                'GET ' + str(urlData['path'].strip()) + str(urlData['query'].strip()) + ' HTTP/1.1',
                'Host: ' + urlData['host'],
                'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/54.0',
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: en-US',
                'Connection: close',
                '\r\n'
            ])

        socketHandler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socketHandler.settimeout(40)
        
        # Usa SSL?
        if(urlData['scheme'] == 'https'):
            socketWraped = ssl.wrap_socket(socketHandler)
        else:
            socketWraped = socketHandler

        socketWraped.connect((str(urlData['host']), int(urlData['port'])))

        socketWraped.send(packet.encode('utf-8', 'ignore'))

        bytesRresponse = b''
        while True:
            bytesPart = socketWraped.recv(1024)
            bytesRresponse = bytesRresponse + bytesPart
            if bytesPart == b'':
                break
        socketWraped.shutdown(1)
        socketWraped.close()

        statusCode = 0
        matches = re.search(br'HTTP\/\d\.\d (\d+) ', bytesRresponse, re.IGNORECASE | re.MULTILINE)
        if(matches):
            statusCode = int(matches.group(1))

        body = bytesRresponse.split(b'\r\n\r\n')
        headers = body.pop(0).strip()
        body = b'\r\n'.join(body)

        # Decodifica las cabeceras
        if(b'\r\n' in headers):
            tmp = {}
            for item in headers.split(b'\r\n'):
                value = item.split(b':')
                key = value.pop(0).strip()
                value = b':'.join(value)
                tmp[key] = value
            headers = tmp

        # Retorna los datos obtenidos
        return {
            'status-code'      : statusCode,
            'response-content' : body,
            'response-headers' : headers,
            'request-content'  : packet
}


if __name__ == '__main__':

    try:
        mainCLS = MainCLS()

    except KeyboardInterrupt:
        # Ctrl+C, it's ok.
        pass

    except Exception as e:
        # Unhandled error
        raise e