import base64
import pickle
import requests
import os
import sys
import utils
import time
from module import Data, Account, Mail
from flask import Flask, jsonify, request, render_template, flash, redirect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
server_node = ['127.0.0.1:5000']
data = Data()
user = None
mailbox = []


@app.route('/', methods=['GET', 'POST'])
def login():
    global user
    load()
    sync()
    if user is not None:
        return render_template('index.html', address=user.address)
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    if data.account_verify.get(username) is None:
        flash('账号或密码错误')
        return render_template('login.html')
    verify_code = data.account_verify[username]
    u = Account(username, password)
    if u.verify(verify_code) is True:
        user = u
        flash('登录成功')
        # response = {
        #     'message': 'success'
        # }
        return redirect('/index')
    else:
        flash('账号或密码错误')
        return render_template('login.html')


@app.route('/logout')
def logout():
    global user
    user = None
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    username = request.form.get('username')
    password = request.form.get('password')
    verify_pass = request.form.get('verify_pass')
    if password != verify_pass:
        flash('请重新输入密码')
        return redirect('/register')
    u = Account(username, password)
    # print(u.address)
    data.addr_key[u.address] = u.get_pub_key().decode()
    # print(data.addr_key[u.address])
    data.account_verify[username] = u.verification
    # print(data.account_verify[username])
    data.timestamp = time.time()
    save()
    flash('注册成功')
    return redirect('/')


@app.route('/compose', methods=['GET', 'POST'])
def compose():
    if user is None:
        return render_template('login.html')
    if request.method == "GET":
        return render_template('compose.html', address=user.address)
    sync()
    to_addr = request.form.get('to')
    # print(to_addr)
    if data.addr_key.get(to_addr) is None:
        return render_template(
            'compose.html',
            msg='要发送的地址不存在',
            address=user.address
        )
    if to_addr == user.address:
        return render_template(
            'compose.html',
            msg='不允许向自己发信',
            address=user.address
        )
    pub_k = data.addr_key[to_addr]
    content = request.form.get('content')
    title = request.form.get('title')
    mail_content = {'from_addr': user.address, 'to_addr': to_addr, 'content': content, 'title': title}
    pri_k = user.get_pri_key().decode()
    mail = Mail(pub_k, mail_content, pri_k)
    for node in server_node:
        response = requests.post('http://{}/send'.format(node), json={
            "mail": seal_message(mail).decode(),
            "to": to_addr,
            "from": user.address
        })
        if response.status_code == 200:
            return render_template(
                'compose.html',
                msg=response.json()['message'],
                address=user.address,
                
            )


@app.route('/index', methods=['GET'])
def index():
    if user is None:
        return render_template('login.html')
    check_mail()
    brief_list = []
    for mail in mailbox:
        brief = {
            'title': mail['title'],
            'from': mail['from_addr'],
            'time': mail['time'],
            'id': mail['id']
        }
        brief_list.append(brief)
    print('brief_list', len(brief_list))
    print(brief_list)
    return render_template(
        'index.html',
        briefs=brief_list,
        address=user.address
    )


@app.route('/mail_reply/<add_to>', methods=['GET','POST'])
def mail_reply(add_to):
    if user is None:
        return render_template('login.html')
    if request.method == "GET":
        return render_template('mail_reply.html', address=user.address, receiver_add =add_to)
    sync()
    #to_addr = request.form.get('to')
    # print(to_addr)
    to_addr = add_to
    if data.addr_key.get(to_addr) is None:
        return render_template(
            'compose.html',
            msg='要发送的地址不存在',
            address=user.address
        )
    if to_addr == user.address:
        return render_template(
            'compose.html',
            msg='不允许向自己发信',
            address=user.address
        )
    pub_k = data.addr_key[to_addr]
    content = request.form.get('content')
    title = request.form.get('title')
    
    mail_content = {'from_addr': user.address, 'to_addr': to_addr, 'content': content, 'title': title}
    pri_k = user.get_pri_key().decode()
    mail = Mail(pub_k, mail_content, pri_k)
    for node in server_node:
        response = requests.post('http://{}/send'.format(node), json={
            "mail": seal_message(mail).decode(),
            "to": to_addr,
            "from": user.address
        })
        if response.status_code == 200:
            return render_template(
                'mail_reply.html',
                msg=response.json()['message'],
                address=user.address,
                receiver_add =add_to
            )

@app.route('/mail/<article_id>', methods=['GET'])
def detail(article_id):
    value_list = []
    for mail in mailbox:
        if mail['id'] == article_id:
            value = {
                'title': mail['title'],
                'from': mail['from_addr'],
                'time': mail['time'],
                'content': mail['content'],
                'id': mail['id']
            }
            value_list.append(value)
            return render_template(
                'detail.html',
                **value,
                reply_to_s=value_list
            )
    
    return redirect('/index.html')


@app.route('/sync', methods=['GET'])
def sync_data():
    response = {
        'data': seal_message(data).decode()
    }
    return jsonify(response), 200


def check_mail():
    mailbox.clear()
    for node in server_node:
        response = requests.post('http://{}/check'.format(node),
                                 json={
                                     'address': user.address
                                 })
        if response.status_code == 200:
            mails = load_message(response.json()['mails'])
            print('mails', len(mails))
            for mail in mails:
                enc = mail.content
                send_time = mail.time
                dec = utils.sm2_decrypt(user.get_pri_key(), enc)
                rec_hash = utils.sm3_hash(base64.b64encode(dec))
                if rec_hash == mail.content_hash:
                    mail_dict = pickle.loads(dec)
                    from_key = data.addr_key[mail_dict['from_addr']].encode()
                    if utils.sm2_verify(from_key, mail.verify, rec_hash):
                        content = {
                            'title': mail_dict['title'],
                            'from_addr': mail_dict['from_addr'],
                            'to_addr': mail_dict['to_addr'],
                            'content': mail_dict['content'],
                            'time': send_time,
                            'id': utils.sm3_hash(mail_dict['content']).decode()[:16]
                        }
                        mailbox.append(content)
    print('mailbox', len(mailbox))


def sync():
    global data
    for node in server_node:
        response = requests.post('http://{}/sync'.format(node), json={"id": 'client'})
        if response.status_code == 200:
            rec_data = load_message(response.json()['data'])
            accounts = len(data.account_verify)
            print(accounts)
            if rec_data.timestamp >= data.timestamp or accounts == 0:
                # print('flag')
                data = rec_data
                print('yes')
    save()


def save():
    db_file = 'node_db/data.db'
    with open(db_file, 'wb') as file:
        pickle.dump(data, file)


def load():
    global data
    db_file = 'node_db/data.db'
    if os.path.getsize(db_file) > 0:
        with open(db_file, 'rb') as file:
            data = pickle.load(file)


def seal_message(message):
    json = base64.b64encode(pickle.dumps(message))
    return json


def load_message(message):
    content = base64.b64decode(message.encode())
    return pickle.loads(content)


if __name__ == "__main__":
    app.run(debug=True, port=5002)