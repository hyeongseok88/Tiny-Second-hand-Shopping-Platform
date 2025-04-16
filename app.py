import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, emit, join_room
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from time import time
from datetime import timedelta


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성 (timestamp 추가)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,  -- 신고 시간 자동 기록
                FOREIGN KEY(reporter_id) REFERENCES user(id),
                FOREIGN KEY(target_id) REFERENCES user(id)
            )
        """)

        # 포인트 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS point (
                user_id TEXT PRIMARY KEY,
                amount INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES user(id)
            )
        """)
        # 차단 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS block (
                id TEXT PRIMARY KEY,
                blocker_id TEXT NOT NULL,
                blocked_username TEXT NOT NULL,
                UNIQUE(blocker_id, blocked_username)
            )
        """)
        # 송금 내역 테이블 추가
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES user(id),
                FOREIGN KEY(receiver_id) REFERENCES user(id)
            )
        """)
        # admin 계정이 있는지 확인
        cursor.execute("SELECT * FROM user WHERE id = ?", ('admin',))
        if cursor.fetchone() is None:
            hashed_password = generate_password_hash("1234")
            print(hashed_password)
            # admin 사용자 추가
            cursor.execute("""
                INSERT INTO user (id, username, password, bio)
                VALUES (?, ?, ?, ?)
            """, ('admin', 'admin', hashed_password, '관리자 계정입니다.'))
            
            # admin 포인트 100,000 추가
            cursor.execute("""
                INSERT INTO point (user_id, amount)
                VALUES (?, ?)
            """, ('admin', 100000))
        
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # 비밀번호 길이 검증
        if len(password) < 8:
            flash('비밀번호는 최소 8자리 이상이어야 합니다.')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        # 초기 포인트 100000원 삽입
        cursor.execute("INSERT INTO point (user_id, amount) VALUES (?, ?)", (user_id, 100000))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 회원탈퇴
@app.route('/deleteuser', methods=['GET'])
def delete_user():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    # 차단 테이블에서 해당 사용자가 차단한 모든 사용자 삭제
    cursor.execute("DELETE FROM block WHERE blocker_id = ?", (user_id,))
    
    # 포인트 정보 삭제
    cursor.execute("DELETE FROM point WHERE user_id = ?", (user_id,))
    
    # 해당 사용자가 등록한 상품 삭제
    cursor.execute("DELETE FROM product WHERE seller_id = ?", (user_id,))
    
    # 사용자 정보 삭제
    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))

    db.commit()

    # 세션 초기화 (로그아웃)
    session.clear()
    flash('회원탈퇴가 완료되었습니다.')
    return redirect(url_for('index'))


# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session.permanent = True
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')
# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 현재 로그인한 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 포인트 조회
    cursor.execute("SELECT amount FROM point WHERE user_id = ?", (session['user_id'],))
    user_point = cursor.fetchone()[0]  # amount만 가져오기
    
    # 차단된 유저 가져오기
    cursor.execute("SELECT blocked_username FROM block WHERE blocker_id = ?", (session['user_id'],))
    blocked_users = [row['blocked_username'] for row in cursor.fetchall()]

    # 검색어 가져오기
    query = request.args.get('q', '')

    # 차단된 유저가 있을 경우, 차단된 사용자 판매 상품 제외
    if blocked_users:
        blocked_users_str = ','.join(['?' for _ in blocked_users])  # Placeholder로 여러 명을 처리
        if query:
            # 검색어가 있을 경우 상품명으로 LIKE 검색, 차단된 판매자 제외
            cursor.execute(f"""
                SELECT * FROM product
                WHERE title LIKE ? AND seller_id NOT IN (SELECT id FROM user WHERE username IN ({blocked_users_str}))
            """, ['%' + query + '%'] + blocked_users)
        else:
            # 검색어 없으면 차단된 판매자 제외한 전체 상품
            cursor.execute(f"""
                SELECT * FROM product
                WHERE seller_id NOT IN (SELECT id FROM user WHERE username IN ({blocked_users_str}))
            """, blocked_users)
    else:
        if query:
            # 검색어가 있을 경우 상품명으로 LIKE 검색
            cursor.execute("SELECT * FROM product WHERE title LIKE ?", ('%' + query + '%',))
        else:
            # 검색어 없으면 전체 상품
            cursor.execute("SELECT * FROM product")
    
    all_products = cursor.fetchall()

    return render_template('dashboard.html', products=all_products, user=current_user, query=query, point=user_point, blocked_users=blocked_users)

# 숫자 콤마 구현
@app.template_filter('comma')
def comma_format(value):
    return "{:,}".format(value)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price_input = request.form['price']

        try:
            price = int(price_input)
        except ValueError:
            flash('가격은 정수로 입력해주세요.')
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')


# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    
    # 현재 로그인한 사용자 정보
    if 'user_id' in session:
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
    else:
        current_user = None
    return render_template('view_product.html', product=product, seller=seller, user=current_user)

# 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 사용자 정보
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 해당 상품이 현재 로그인한 사용자의 것인지 확인
    if product['seller_id'] != session['user_id']:
        flash('본인의 상품만 삭제할 수 있습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()

    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

#상품 수정
@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()

    # 상품 정보 가져오기
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 판매자 확인
    if 'user_id' not in session or product['seller_id'] != session['user_id']:
        flash('이 상품을 수정할 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # 폼에서 수정된 데이터 가져오기
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']

        # 상품 수정 쿼리 실행
        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, price = ?
            WHERE id = ?
        """, (title, description, price, product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)

@app.context_processor
def inject_user():
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        return dict(user=user)
    return dict(user=None)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트
    
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        
        # 사용자 존재 여부 확인 (신고 대상이 실제 사용자여야 합니다)
        db = get_db()
        cursor = db.cursor()
        
        try:
            cursor.execute("SELECT id FROM user WHERE username = ?", (target_id,))
            target_user = cursor.fetchone()
            
            if not target_user:
                flash('존재하지 않는 사용자입니다.')
                return redirect(url_for('report'))  # 신고 페이지로 리다이렉트
            
            # 신고 ID 생성 (UUID)
            report_id = str(uuid.uuid4())
            
            # 신고 내역 테이블에 저장
            cursor.execute("""
                INSERT INTO report (id, reporter_id, target_id, reason) 
                VALUES (?, ?, ?, ?)
            """,  (report_id, session['user_id'], target_user[0], reason))
            
            db.commit()
            flash('신고가 접수되었습니다.')
            return redirect(url_for('dashboard'))  # 대시보드로 리다이렉트
        except Exception as e:
            db.rollback()  # 실패 시 롤백
            flash(f"오류 발생: {str(e)}")
            return redirect(url_for('report'))  # 오류 발생 시 신고 페이지로 리다이렉트
    
    return render_template('report.html')



# 송금 시스템
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']

    # 사용자 정보와 포인트 불러오기
    cursor.execute("SELECT username FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    cursor.execute("SELECT amount FROM point WHERE user_id = ?", (user_id,))
    point = cursor.fetchone()
    point_amount = point['amount'] if point else 0

    if request.method == 'POST':
        target_username = request.form['target_username']
        amount = int(request.form['amount'])

        # 수신자 ID 조회
        cursor.execute("SELECT id FROM user WHERE username = ?", (target_username,))
        target = cursor.fetchone()

        if not target:
            flash('해당 사용자 이름이 존재하지 않습니다.')
            return redirect(url_for('transfer'))

        receiver_id = target['id']

        # 송금 가능 여부 확인
        if point_amount < amount:
            flash('보유한 포인트가 부족합니다.')
            return redirect(url_for('transfer'))

        # 송금 처리
        cursor.execute("UPDATE point SET amount = amount - ? WHERE user_id = ?", (amount, user_id))

        cursor.execute("SELECT amount FROM point WHERE user_id = ?", (receiver_id,))
        receiver_point = cursor.fetchone()

        if receiver_point:
            cursor.execute("UPDATE point SET amount = amount + ? WHERE user_id = ?", (amount, receiver_id))
        else:
            cursor.execute("INSERT INTO point (user_id, amount) VALUES (?, ?)", (receiver_id, amount))

        # 송금 내역 기록 추가 (시간 자동으로 기록)
        cursor.execute("""
            INSERT INTO transfer_history (sender_id, receiver_id, amount)
            VALUES (?, ?, ?)
        """, (user_id, receiver_id, amount))

        db.commit()

        flash(f"{target_username}님에게 {amount:,}원 송금 완료!")
        return redirect(url_for('dashboard'))

    return render_template('transfer.html', user=user, point=point_amount)

#차단하기
@app.route('/block', methods=['GET', 'POST'])
def block_user():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    # 현재 로그인한 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if request.method == 'POST':
        # 차단 해제 요청 처리
        if 'unblock_username' in request.form:
            unblock_username = request.form['unblock_username']
            cursor.execute(
                "DELETE FROM block WHERE blocker_id = ? AND blocked_username = ?",
                (user_id, unblock_username)
            )
            db.commit()
            flash(f"{unblock_username}님의 차단을 해제했습니다.")
            return redirect(url_for('block_user'))

        # 차단 요청 처리
        target_username = request.form.get('target_username')

        if target_username:
            # 자기 자신을 차단하는지 체크
            if target_username == current_user['username']:
                flash('자기 자신을 차단할 수 없습니다.')
                return redirect(url_for('block_user'))

            cursor.execute("SELECT id FROM user WHERE username = ?", (target_username,))
            target_user = cursor.fetchone()

            if not target_user:
                flash('해당 사용자가 존재하지 않습니다.')
                return redirect(url_for('block_user'))

            block_id = str(uuid.uuid4())
            try:
                cursor.execute(
                    "INSERT INTO block (id, blocker_id, blocked_username) VALUES (?, ?, ?)",
                    (block_id, user_id, target_username)
                )
                db.commit()
                flash(f"{target_username}님을 차단했습니다.")
            except sqlite3.IntegrityError:
                flash('이미 차단된 사용자입니다.')

            return redirect(url_for('block_user'))

    # 차단 목록 가져오기
    cursor.execute("SELECT blocked_username FROM block WHERE blocker_id = ?", (user_id,))
    blocked_users = cursor.fetchall()

    return render_template('block_user.html', blocked_users=blocked_users)



# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    user_id = session.get('user_id')
    target_username = data['username']
    
    # 현재 시간을 가져옵니다.
    current_time = time()
    
    # 사용자 세션에서 전송 기록을 가져옵니다.
    message_times = session.get('message_times', [])
    
    # 메시지 전송 기록이 3개 이상이고, 그 중 3번은 최근 4초 이내에 보내졌다면
    if len(message_times) >= 3 and (current_time - message_times[0]) < 4:
        return
    
    # 메시지를 보낸 시간 기록
    message_times.append(current_time)
    
    # 시간 초과된 기록은 삭제 (10초가 지난 메시지는 기록에서 제외)
    message_times = [time for time in message_times if current_time - time < 10]
    
    # 세션에 업데이트된 메시지 전송 시간을 저장
    session['message_times'] = message_times
    
    # 차단된 사용자 목록 확인
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT blocked_username FROM block WHERE blocker_id = ?", (user_id,))
    blocked_users = cursor.fetchall()
    blocked_usernames = [blocked['blocked_username'] for blocked in blocked_users]

    # 차단된 사용자의 메시지 처리
    if target_username not in blocked_usernames:
        # 차단되지 않은 사용자의 메시지일 경우 브로드캐스트
        data['message_id'] = str(uuid.uuid4())
        send(data, broadcast=True)


#1:1 채팅     
user_sid_map = {}  # username → sid

@socketio.on('register_user')
def handle_register_user(data):
    username = data['username']
    user_sid_map[username] = request.sid
    join_room(username)  # 닉네임 기준으로 방 만들기
    print(f"User {username} registered with sid {request.sid}")

@socketio.on('private_message')
def handle_private_message(data):
    target = data['to']
    sender = data['from']
    message = data['message']
    message_id = str(uuid.uuid4())
    # 메시지 길이가 20자를 초과하면 경고 메시지 발송하고 종료
    if len(message) > 30:
        error_message = "메시지는 30자를 초과할 수 없습니다."
        emit('private_message', {
            'username': '시스템',
            'message': error_message,
            'message_id': message_id
        }, room=request.sid)
        return  # 메시지 전송을 중지

    print(f"Received message from {sender} to {target}: {message}")

    # 세션에서 보낸 사람의 user_id 가져오기
    sender_id = session.get('user_id')

    db = get_db()
    cursor = db.cursor()

    # sender가 target을 차단했는지 확인
    cursor.execute("""
        SELECT 1 FROM block 
        WHERE blocker_id = ? 
        AND blocked_username = ?
    """, (sender_id, target))
    sender_blocked = cursor.fetchone()

    # target의 user_id 조회
    cursor.execute("""
        SELECT id FROM user
        WHERE username = ?
    """, (target,))
    target_user = cursor.fetchone()

    if target_user:
        target_id = target_user[0]

        # target이 sender를 차단했는지 확인
        cursor.execute("""
            SELECT 1 FROM block 
            WHERE blocker_id = ? 
            AND blocked_username = ?
        """, (target_id, sender))
        target_blocked = cursor.fetchone()
    else:
        target_blocked = None  # 대상이 없으면 차단 처리하지 않음

    # 둘 중 하나라도 차단한 경우 메시지 전송 중지
    if sender_blocked or target_blocked:
        print(f"Message blocked between {sender} and {target}.")
        emit('private_message', {
            'username': '시스템',
            'message': '이 사용자와의 채팅이 차단되어 메시지를 보낼 수 없습니다.',
            'message_id': message_id
        }, room=request.sid)
        return

    # 차단되지 않은 경우 메시지 전송
    if target in user_sid_map:
        target_sid = user_sid_map[target]
        print(f"Sending message to {target} (sid: {target_sid})")

        # 대상에게 메시지 보내기
        emit('private_message', {
            'username': sender,
            'message': message,
            'message_id': message_id
        }, room=target_sid)

        # 보낸 사람에게도 메시지 확인용으로 보내기
        emit('private_message', {
            'username': sender,
            'message': message,
            'message_id': message_id
        }, room=request.sid)

    else:
        # 대상이 오프라인인 경우
        print(f"[ERROR] User {target} not found!")
        emit('private_message', {
            'username': '시스템',
            'message': '대상 사용자가 온라인 상태가 아닙니다.',
            'message_id': message_id
        }, room=request.sid)




@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # 로그인 페이지로 리디렉션
    
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    username = current_user['username']
    
    return render_template('chat.html', username=username)


#관리자 기능

# 사용자 정보 페이지 (회원 목록과 삭제 기능)
@app.route('/user_info', methods=['GET'])
def user_info():
    # 로그인 상태 확인
    if 'user_id' not in session or session['user_id'] != 'admin':
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트
    db = get_db()
    cursor = db.cursor()

    # 모든 사용자 조회
    cursor.execute("SELECT id, username FROM user")
    users = cursor.fetchall()

    # 사용자별 포인트 조회
    user_points = {}
    for user in users:
        cursor.execute("SELECT amount FROM point WHERE user_id = ?", (user[0],))
        point = cursor.fetchone()
        user_points[user[0]] = point[0] if point else 0

    return render_template('user_info.html', users=users, user_points=user_points)

# 계정 삭제
@app.route('/delete_userinfo/<user_id>', methods=['POST'])
def delete_userinfo(user_id):
    # 로그인 상태 확인
    if 'user_id' not in session or session['user_id'] != 'admin':
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트
    db = get_db()
    cursor = db.cursor()

    # 사용자의 포인트 정보 삭제
    cursor.execute("DELETE FROM point WHERE user_id = ?", (user_id,))
    # 사용자의 상품 정보 삭제
    cursor.execute("DELETE FROM product WHERE seller_id = ?", (user_id,))
    # 포인트 정보 삭제
    cursor.execute("DELETE FROM point WHERE user_id = ?", (user_id,))
    # 사용자의 차단 정보 삭제
    cursor.execute("DELETE FROM block WHERE blocker_id = ? OR blocked_username = ?", (user_id, user_id))
    
    # 신고 테이블에서 해당 사용자가 신고한 내용 삭제 (reporter_id로 삭제)
    cursor.execute("DELETE FROM report WHERE reporter_id = ?", (user_id,))
    
    # 신고 테이블에서 해당 사용자가 신고 당한 내용 삭제 (target_id로 삭제)
    cursor.execute("DELETE FROM report WHERE target_id = ?", (user_id,))
    # 사용자 삭제
    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))

    db.commit()
    flash('사용자가 삭제되었습니다.')
    return redirect(url_for('user_info'))

#유저 상품 관리
@app.route('/user_product')
def product_manage():
    # 로그인 상태 확인
    if 'user_id' not in session or session['user_id'] != 'admin':
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT product.*, user.username as seller_name
        FROM product
        JOIN user ON product.seller_id = user.id
    """)
    products = cursor.fetchall()
    return render_template('user_product.html', products=products)
@app.route('/product/delete/<product_id>', methods=['POST'])
def user_product_delete(product_id):
    # 로그인 상태 확인 및 관리자 권한 체크
    if 'user_id' not in session or session['user_id'] != 'admin':
        flash('관리자만 상품을 삭제할 수 있습니다.')
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트

    db = get_db()
    cursor = db.cursor()

    # 상품 존재 여부 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('product_manage'))

    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()

    flash("상품이 삭제되었습니다.")
    return redirect(url_for('product_manage'))

# 송금 내역 페이지 조회
@app.route('/transfer_history')
def transfer_history():
    # 로그인 상태 확인
    if 'user_id' not in session or session['user_id'] != 'admin':
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트

    db = get_db()
    cursor = db.cursor()

    # 송금 내역 가져오기 (보낸 사람, 받은 사람, 금액, 송금 시간)
    cursor.execute("""
        SELECT t.id, t.sender_id, u1.username AS sender_username, t.receiver_id, u2.username AS receiver_username, t.amount, t.timestamp
        FROM transfer_history t
        JOIN user u1 ON t.sender_id = u1.id
        JOIN user u2 ON t.receiver_id = u2.id
        ORDER BY t.timestamp DESC
    """)

    transfers = cursor.fetchall()

    return render_template('transfer_history.html', transfers=transfers)


# 송금 내역 삭제
@app.route('/delete_transfer_history/<transfer_id>', methods=['POST'])
def delete_transfer_history(transfer_id):
    if 'user_id' not in session or session['user_id'] != 'admin':
        flash('관리자만 삭제할 수 있습니다.')
        return redirect(url_for('transfer_history'))

    db = get_db()
    cursor = db.cursor()

    # 해당 송금 내역 삭제
    cursor.execute("DELETE FROM transfer_history WHERE id = ?", (transfer_id,))
    db.commit()

    flash("송금 내역이 삭제되었습니다.")
    return redirect(url_for('transfer_history'))

# 신고 내역 조회
@app.route('/report_history')
def report_history():
    if 'user_id' not in session or session['user_id'] != 'admin':
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트

    db = get_db()
    cursor = db.cursor()

    # 신고 내역 가져오기 (timestamp 추가)
    cursor.execute("""
        SELECT r.id, r.reporter_id, u1.username AS reporter_username, r.target_id, u2.username AS target_username, r.reason, r.timestamp
        FROM report r
        JOIN user u1 ON r.reporter_id = u1.id  -- 신고자 이름 가져오기
        JOIN user u2 ON r.target_id = u2.id    -- 신고 대상 이름 가져오기
        ORDER BY r.timestamp DESC  -- 신고 시간 기준으로 내림차순 정렬
    """)

    reports = cursor.fetchall()

    return render_template('report_history.html', reports=reports)




# 신고 내역 삭제
@app.route('/delete_report/<report_id>', methods=['POST'])
def delete_report(report_id):
    if 'user_id' not in session or session['user_id'] != 'admin':
        return redirect(url_for('login'))  # 로그인 페이지로 리다이렉트

    db = get_db()
    cursor = db.cursor()

    # 신고 내역 삭제
    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()

    flash('신고 내역이 삭제되었습니다.')
    return redirect(url_for('report_history'))

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=False)
