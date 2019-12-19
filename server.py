import requests
import base64
import pickle
import os
import utils
import time
from module import BlockChain, Data, Mail, Block
from flask import Flask, jsonify, request


app = Flask(__name__)

server_neighbours = ['127.0.0.1:5001']
client_neighbours = ['127.0.0.1:5002', '127.0.0.1:5003']
chain = BlockChain()
# send_mails = []
waiting_mail = []
# recv_mails = []
data = Data()
new_blocks = []


@app.route('/', methods=['GET'])
def start():
    global chain
    global data
    global new_blocks
    chain.load()
    sync()
    if chain.get_length() < 1:
        from_k = utils.get_private_key().decode()
        to_k = utils.get_public_key(from_k).decode()
        c = {
            'title': 'abc',
            'content': '123',
            'to': to_k,
            'from': from_k
        }
        mail = Mail(to_k, c, from_k)
        b = Block()
        b.add_mail(mail)
        chain.add_block(b)
        new_blocks.append(b)
        data = pickle.loads(chain.last_block().data)
        chain.save()
    data = pickle.loads(chain.last_block().data)
    response = {
        'message': "OK, is fine!",
        'block_hash': chain.last_block().hash.decode(),
        'length': chain.get_length(),
        'accounts': len(data.account_verify)
    }
    # mail_chain.save()
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    global waiting_mail
    global new_blocks
    sync()
    if len(waiting_mail) < 1:
        from_k = utils.get_private_key().decode()
        to_k = utils.get_public_key(from_k).decode()
        c = {
            'title': '000',
            'content': '000',
            'to': to_k,
            'from': from_k
        }
        m = Mail(to_k, c, from_k)
        mail = {
            'content': m,
            'to': '000',
            'from': '000'
        }
        waiting_mail.append(mail)

    print(len(waiting_mail))
    block = Block()
    b_loc = chain.last_block().index + 1
    for mail in waiting_mail:
        index = block.add_mail(mail['content'])
        to_addr = mail['to']
        from_addr = mail['from']
        location = [b_loc, index]
        if data.addr_rec_mail.get(to_addr) is None:
            data.addr_rec_mail[to_addr] = []
        data.addr_rec_mail[to_addr].append(location)
        print(to_addr, location)
        if data.addr_send_mail.get(from_addr) is None:
            data.addr_send_mail[from_addr] = []
        data.addr_send_mail[from_addr].append(location)
    waiting_mail.clear()
    block.data = pickle.dumps(data)
    chain.add_block(block)
    chain.save()
    new_blocks.append(block)
    response = {
        'message': 'new block is mined',
        'block_index': chain.last_block().index,
        'block_hash': chain.last_block().hash.decode(),
        'block_nonce': chain.last_block().nonce
    }
    for node in server_neighbours:
        requests.get('http://{}/'.format(node))
    return jsonify(response), 200


@app.route('/send', methods=['POST'])
def send():
    sync()
    rec = request.get_json()
    mail = {'content': load_message(rec.get('mail')), 'to': rec.get('to'), 'from': rec.get('from')}
    waiting_mail.append(mail)
    response = {
        'message': '已进入等待队列'
    }
    return jsonify(response), 200


@app.route('/check', methods=['POST'])
def check_mail():
    sync()
    addr = request.get_json().get('address')
    print(addr)
    rec_list = []
    if data.addr_rec_mail.get(addr) is not None:
        rec_list = data.addr_rec_mail[addr]
    mails = []
    for pos in rec_list:
        b = pos[0]
        m = pos[1]
        block = chain.find_block(b)
        mail = block.find_mail(m)
        mails.append(mail)
    response = {
        'mails': seal_message(mails).decode()
    }
    return jsonify(response), 200


@app.route('/sync', methods=['POST'])
def sync_data():
    global new_blocks
    global data
    #sync()
    
    e_id = request.get_json().get('id')
    if e_id is not None and e_id == 'server':
        response = {
            'length': chain.get_length(),
            'block': seal_message(new_blocks).decode()
        }
        new_blocks = []
        print(response)
    else:
        response = {
            'data': seal_message(data).decode()  # data被dumps序列化
        }
        print(response)
    return jsonify(response), 200
    
    #return 'ok',200


def sync():
    global chain
    global data
    header = {
        'Connection': 'close'
    }
    for node in server_neighbours:
        #response = requests.post('http://{}/sync'.format(node), json={'id': 'server'})
        try:
            
            response = requests.post('http://{}/sync'.format(node), json={'id': 'server'})
           # print(type(response.status_code))
            if response.status_code == 200:
                print('ready!')
                length = response.json()['length']
                print(length)
                print(type(length))
                rec_blocks = load_message(response.json()['block'])
                if chain.get_length() == 0:
                    for block in rec_blocks:
                        chain.add_block(block)

                if length > chain.get_length():
                    print(rec_blocks)
                    for block in rec_blocks:
                        if chain.validate(block) is True:
                            chain.add_block(block)
            print('done!')
        except:
            time.sleep(0.1)
            continue

    for node in client_neighbours:
        try:
            response = requests.get('http://{}/sync'.format(node),headers=header)
            if response.status_code == 200:
                rec_data = load_message(response.json()['data'])
                if rec_data.timestamp > data.timestamp:
                    print('yes')
                    data.account_verify.update(rec_data.account_verify)
                    data.addr_key.update(rec_data.addr_key)
                    data.timestamp = rec_data.timestamp
        except:
            time.sleep(0.1)
            continue


def seal_message(message):
    json = base64.b64encode(pickle.dumps(message))
    return json


def load_message(message):
    content = base64.b64decode(message.encode())
    return pickle.loads(content)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
