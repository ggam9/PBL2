from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
import bcrypt, os
from datetime import datetime
from datetime import timedelta
from werkzeug.utils import secure_filename
from flask import send_from_directory
from collections import defaultdict
app = Flask(__name__)

# 파일 업로드 관리리
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file(file, directory_path):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(directory_path, filename)
        file.save(file_path)
        return filename.replace('\\', '/')  # 슬래시로 변환하여 반환
    return None
# 세션 설정
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 1시간 후 자동 만료
app.config['SESSION_PERMANENT'] = False  # 브라우저가 꺼지면 세션 삭제

# 데이터베이스 파일 경로 설정
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, 'site.db')

# SQLAlchemy 설정
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

socketio = SocketIO(app, cors_allowed_origins="*")
active_users = {
    2: {  # 그룹 ID가 2인 경우
        '다른 접속자가 없습니다': datetime.now(),
    }
}



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    last_accessed = db.Column(db.DateTime, nullable=True)
    joined_posts = db.relationship('PostUser', back_populates='user')
    total_study_time = db.Column(db.Integer, default=0)  # Total study time in seconds

    def __repr__(self):
        return f"User('{self.username}')"


# 회원가입 폼 정의
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=35)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Sign Up')

# 로그인 폼 정의
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=35)])
    submit = SubmitField('Login')
    
# 게시글 모델 정의
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    max_participants = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    participants = db.relationship('PostUser', back_populates='post', cascade="all, delete-orphan")

    def __repr__(self):
        return f"Post('{self.title}', '{self.topic}')"

class PostUser(db.Model):
    __tablename__ = 'post_user'
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    role = db.Column(db.String(20), default='member')
    post = db.relationship('Post', back_populates='participants')
    user = db.relationship('User', back_populates='joined_posts')
    study_time = db.Column(db.Integer, default=0)
    def __repr__(self):
        return f"PostUser('{self.post_id}', '{self.user_id}', '{self.role}')"
    
class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    def __repr__(self):
        return f"Schedule('{self.title}', '{self.date}')"

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    def __repr__(self):
        return f"Announcement('{self.title}', '{self.created_at}')"

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    image = db.Column(db.String(255), nullable=True)  # 이미지 경로 저장
    difficulty = db.Column(db.String(50), nullable=False)
    answer = db.Column(db.String(255), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    score = db.Column(db.Integer)

    def __repr__(self):
        return f"Quiz('{self.question}', '{self.difficulty}')"


class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id= db.Column(db.String, db.ForeignKey('user.id'), nullable=False)
    to_user = db.Column(db.String, nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
  # 관계 설정 (User 객체 참조)
    from_user = db.relationship('User', backref='sent_messages', foreign_keys=[from_user_id])

    def __repr__(self):
        return f"PrivateMessage('{self.from_user}', '{self.to_user}', '{self.message}')"





# 라우트 정의
@app.route('/')
def root():
    return redirect(url_for('beginer'))

@app.route('/beginer')
def beginer():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    return render_template('beginer.html')



# 보호된 index2 페이지
@app.route('/index2')
def index2():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    posts = Post.query.all()
    return render_template('index2.html', posts=posts, logged_in=True)


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', post=post)

@app.route('/join/<int:post_id>', methods=['POST'])
def join_post(post_id):
    if 'user_id' not in session:
        flash('Please log in to join a post', 'warning')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    post = db.session.get(Post, post_id)
    if not any(pu.user_id == user.id for pu in post.participants):
        if len(post.participants) < post.max_participants:
            new_post_user = PostUser(post_id=post.id, user_id=user.id)
            db.session.add(new_post_user)
            db.session.commit()
            flash('Successfully joined the post!', 'success')
        else:
            flash('This post has reached the maximum number of participants.', 'danger')
    return redirect(url_for('search_group'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password):
            session['user_id'] = user.id
            session['username'] = user.username  # ✅ 사용자 이름도 세션에 저장
            session.permanent = False  # 브라우저 닫으면 세션 만료
            flash('Login successful!', 'success')
            return redirect(url_for('root'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()    
    flash('로그아웃 되었습니다.', 'info')
    return redirect(url_for('login'))


@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if 'user_id' not in session:
        flash('Please log in to create a post', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        topic = request.form['topic']
        content = request.form['content']
        max_participants = request.form['max_participants']  # 최대 인원수
        new_post = Post(title=title, topic=topic, content=content, max_participants=int(max_participants))
        db.session.add(new_post)
        db.session.commit()

        # 그룹 생성자를 자동으로 참가시키고 리더로 설정
        user = db.session.get(User, session['user_id'])
        new_post_user = PostUser(post_id=new_post.id, user_id=user.id, role='leader')
        db.session.add(new_post_user)
        db.session.commit()

        flash('Post created successfully and you are now the leader!', 'success')
        return redirect(url_for('search_group'))
    return render_template('create_post.html')


@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        post.title = request.form['title']
        post.topic = request.form['topic']
        post.content = request.form['content']
        post.max_participants = int(request.form['max_participants'])
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('search_group'))
    return render_template('edit_post.html', post=post)

@app.route('/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('search_group'))

@app.route('/group/<int:post_id>', methods=['GET', 'POST'])
def group_page(post_id):
    if 'user_id' not in session:
        flash('Please log in to access the group', 'warning')
        return redirect(url_for('login'))
    
    post = db.session.get(Post, post_id)
    user = db.session.get(User, session['user_id'])
    
    if not any(pu.user_id == user.id for pu in post.participants):
        flash('You must join the group to manage it.', 'warning')
        return redirect(url_for('search_group'))

    
    return render_template('group_page.html', post=post)

@app.route('/group/<int:post_id>/announcement', methods=['GET', 'POST'])
def group_announcement(post_id):
    if 'user_id' not in session:
        flash('Please log in to view announcements', 'warning')
        return redirect(url_for('login'))
    
    post = db.session.get(Post, post_id)
    current_user = db.session.get(User, session['user_id'])
    current_role = next((pu.role for pu in post.participants if pu.user_id == current_user.id), 'member')
    
    if request.method == 'POST':
        # Only leaders or admins can create, edit, or delete announcements
        if current_role not in ['leader', 'admin']:
            flash('Only admins or leaders can manage announcements.', 'danger')
            return redirect(url_for('group_page', post_id=post_id))
        
        action = request.form.get('action')
        if action == 'create':
            title = request.form['title']
            content = request.form['content']
            new_announcement = Announcement(title=title, content=content, post_id=post_id)
            db.session.add(new_announcement)
            db.session.commit()
            flash('Announcement created successfully!', 'success')
        elif action == 'edit':
            ann_id = int(request.form['ann_id'])
            announcement = Announcement.query.get_or_404(ann_id)
            announcement.title = request.form['title']
            announcement.content = request.form['content']
            db.session.commit()
            flash('Announcement updated successfully!', 'success')
        elif action == 'delete':
            ann_id = int(request.form['ann_id'])
            announcement = Announcement.query.get_or_404(ann_id)
            db.session.delete(announcement)
            db.session.commit()
            flash('Announcement deleted successfully!', 'success')

    # Fetch announcements to display to all members
    announcements = Announcement.query.filter_by(post_id=post_id).order_by(Announcement.created_at.desc()).all()
    return render_template('group_announcement.html', post=post, announcements=announcements, current_role=current_role)

@app.route('/group_chat/<int:post_id>') 
def group_chat(post_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    post = Post.query.get_or_404(post_id) 
    participants = [pu.user for pu in post.participants]
       
    return render_template('group_chat.html', post=post,participants=participants)
#-----------------------------------------------------------------
#실시간조회목록 띄우기
# 유저 접속자 정보
active_users2 = defaultdict(set)  # post_id: set(usernames)
user_socket_map = {}  # sid: (username, post_id)

@socketio.on('join_room', namespace='/groupchat')
def handle_join_room(data):
    room = data.get('room')  # e.g., "post_3"
    post_id = str(data.get('post_id'))
    username = data.get('username')

    if room and post_id and username:
        join_room(room)
        active_users2[post_id].add(username)
        user_socket_map[request.sid] = (username, post_id)

        emit('update_active_users', list(active_users2[post_id]), room=room)
        print(f"[groupchat] {username} joined room {room}")

@socketio.on('disconnect', namespace='/groupchat')
def handle_disconnect():
    sid = request.sid
    user_info = user_socket_map.pop(sid, None)

    if user_info:
        username, post_id = user_info
        room = f'post_{post_id}'

        active_users[post_id].discard(username)
        emit('update_active_users', list(active_users[post_id]), room=room)
        print(f"[groupchat] {username} disconnected from room {room}")
   
#-----------------------------------------------------------------

@socketio.on('group_message',namespace='/groupchat')
def handle_group_message(data):
    room = data.get('room')
    msg = data.get('msg')
    user_id = session.get('user_id')

    user = User.query.get(user_id)
    if not user:
       print(f"[group_message] Invalid user ID: {user_id}")
       return

    print(f"[group_message] ({room}) {user.username}: {msg}")

    emit('group_message', {
        'username': user.username,
        'msg': msg
    }, room=room)
    


@socketio.on("private_message",namespace='/groupchat')
def handle_private_message(data):
    from_username = data["from"]
    to_username = data["to"]
    message = data["message"]

    # username → user object → id
    from_user = User.query.filter_by(username=from_username).first()
    to_user = User.query.filter_by(username=to_username).first()

    if not from_user or not to_user:
        return  # 사용자 없으면 무시하거나 예외 처리

    # DB 저장
    pm = PrivateMessage(from_user_id=from_user.id, to_user=to_username, message=message)
    db.session.add(pm)
    db.session.commit()

    room = get_private_room(from_username, to_username)
    join_room(room)
    emit("private_message", {"from": from_username, "message": message}, room=room)


@socketio.on("load_private_chat",namespace='/groupchat')
def handle_load_private_chat(data):
    from_username = data["from"]
    to_username = data["to"]

    from_user = User.query.filter_by(username=from_username).first()
    to_user = User.query.filter_by(username=to_username).first()

    if not from_user or not to_user:
        return

    # 메시지 로드 (username 기준)
    messages = PrivateMessage.query.filter(
        ((PrivateMessage.from_user_id == from_user.id) & (PrivateMessage.to_user == to_username)) |
        ((PrivateMessage.from_user_id == to_user.id) & (PrivateMessage.to_user == from_username))
    ).order_by(PrivateMessage.timestamp.asc()).all()

    formatted = [{"from": User.query.get(m.from_user_id).username, "message": m.message} for m in messages]

    room = get_private_room(from_username, to_username)
    join_room(room)
    emit("load_private_chat", {"messages": formatted})


def get_private_room(user1, user2):
    return "_".join(sorted([user1, user2]))




@app.route('/group/<int:post_id>/share', methods=['GET', 'POST'])
def group_share(post_id):
    if 'user_id' not in session:
        flash('Please log in to access the file sharing page.', 'warning')
        return redirect(url_for('login'))
    
    post = db.session.get(Post, post_id)
    group_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(post_id))

    # 미리 정의된 디렉토리
    predefined_directories = ['documents', 'images', 'videos']
    for directory in predefined_directories:
        path = os.path.join(group_folder, directory)
        if not os.path.exists(path):
            os.makedirs(path)

    if request.method == 'POST':
        file = request.files['file']
        subdirectory = request.form.get('subdirectory')
        if subdirectory in predefined_directories:
            subdirectory_path = os.path.join(group_folder, subdirectory)
            filename = upload_file(file, subdirectory_path)
            if filename:
                flash('File successfully uploaded', 'success')
            else:
                flash('Invalid file type', 'danger')
        else:
            flash('Invalid directory', 'danger')
        return redirect(url_for('group_share', post_id=post_id))
    
    # 그룹별 파일 목록
    dirs_and_files = []
    if os.path.exists(group_folder):
        for root, dirs, filenames in os.walk(group_folder):
            for name in filenames:
                dirs_and_files.append(os.path.relpath(os.path.join(root, name), group_folder))
            for name in dirs:
                dirs_and_files.append(os.path.relpath(os.path.join(root, name), group_folder) + '/')

    return render_template('group_share.html', post=post, dirs_and_files=dirs_and_files)

@app.route('/group/<int:post_id>/download/<path:filename>', methods=['GET'])
def download_file(post_id, filename):
    group_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(post_id))
    # URL 경로에서 슬래시를 사용하도록 수정
    file_path = filename.replace('\\', '/')
    return send_from_directory(group_folder, file_path, as_attachment=True)

@app.route('/group/<int:post_id>/delete/<path:filename>', methods=['POST'])
def delete_file(post_id, filename):
    if 'user_id' not in session:
        flash('Please log in to delete files.', 'warning')
        return redirect(url_for('login'))
    
    group_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(post_id))
    file_path = os.path.join(group_folder, filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('File deleted successfully', 'success')
    else:
        flash('File not found', 'danger')
    
    return redirect(url_for('group_share', post_id=post_id))
@app.route('/group/<int:post_id>/members', methods=['GET', 'POST'])
def group_members(post_id):
    if 'user_id' not in session:
        flash('Please log in to manage members', 'warning')
        return redirect(url_for('login'))
    
    post = db.session.get(Post, post_id)
    current_user = db.session.get(User, session['user_id'])
    post_users = PostUser.query.filter_by(post_id=post_id).all()

    # 현재 사용자가 대표인지 확인
    current_role = next((pu.role for pu in post_users if pu.user_id == current_user.id), 'member')
    
    # POST 요청 처리 (대표/관리자 임명 및 제명)
    if request.method == 'POST':
        action = request.form.get('action')
        target_user_id = int(request.form.get('user_id'))
        target_post_user = next((pu for pu in post_users if pu.user_id == target_user_id), None)
        
        if action == 'promote' and current_role == 'leader':
            if target_post_user:
                if request.form.get('role') == 'leader':
                    target_post_user.role = 'leader'
                    current_post_user = next((pu for pu in post_users if pu.user_id == current_user.id), None)
                    if current_post_user:
                        current_post_user.role = 'admin'
                elif request.form.get('role') == 'admin':
                    target_post_user.role = 'admin'
                elif request.form.get('role') == 'member':
                    target_post_user.role = 'member'
        elif action == 'remove' and current_role in ['leader', 'admin']:
            if target_post_user:
                db.session.delete(target_post_user)
        
        db.session.commit()
        flash('Member role updated successfully!', 'success')
    
    return render_template('group_members.html', post=post, post_users=post_users, current_role=current_role)

@app.route('/group/<int:post_id>/quiz', methods=['GET', 'POST'])
def group_quiz(post_id):
    if 'user_id' not in session:
        flash('Please log in to manage quizzes', 'warning')
        return redirect(url_for('login'))
    
    post = db.session.get(Post, post_id)
    quiz_image_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(post_id), 'quiz_images')
    if not os.path.exists(quiz_image_folder):
        os.makedirs(quiz_image_folder)

    if request.method == 'POST':
        question = request.form['question']
        image_file = request.files.get('image')
        image_filename = upload_file(image_file, quiz_image_folder) if image_file else None
        difficulty = request.form['difficulty']
        answer = request.form['answer']
        if image_filename:
            # 경로 구분자를 '/'로 변경하여 저장
            image_path = f"{post_id}/quiz_images/{image_filename}"
        else:
            image_path = None
        new_quiz = Quiz(question=question, image=image_path, difficulty=difficulty, answer=answer, post_id=post_id)
        db.session.add(new_quiz)
        db.session.commit()
        flash('Quiz created successfully!', 'success')
    
    quizzes = Quiz.query.filter_by(post_id=post_id).all()
    return render_template('group_quiz.html', post=post, quizzes=quizzes)

@app.route('/group/<int:post_id>/quiz/<int:quiz_id>', methods=['GET', 'POST'])
def take_quiz(post_id, quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if request.method == 'POST':
        user_answer = request.form['answer']
        if user_answer.lower().strip() == quiz.answer.lower().strip():
            flash('Correct!', 'success')
        else:
            flash(f'Incorrect. The correct answer is: {quiz.answer}', 'danger')
        return redirect(url_for('take_quiz', post_id=post_id, quiz_id=quiz.id))
    
    next_quiz = Quiz.query.filter(Quiz.post_id == post_id, Quiz.id > quiz_id).order_by(Quiz.id).first()
    return render_template('take_quiz.html', quiz=quiz, next_quiz=next_quiz)

from flask import jsonify

@app.route('/group/<int:post_id>/quiz/<int:quiz_id>/check_answer', methods=['POST'])
def check_answer(post_id, quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    user_answer = request.json.get('answer')
    correct = user_answer.lower().strip() == quiz.answer.lower().strip()
    return jsonify(correct=correct, correct_answer=quiz.answer)

@app.route('/group/<int:post_id>/quiz/<int:quiz_id>/delete', methods=['POST'])
def delete_quiz(post_id, quiz_id):
    if 'user_id' not in session:
        flash('Please log in to manage quizzes', 'warning')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.image:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], str(post_id), 'quiz_images', quiz.image)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz deleted successfully!', 'success')
    return redirect(url_for('group_quiz', post_id=post_id))

@app.route('/group/<int:post_id>/calender', methods=['Get', 'POST'])
def group_calender(post_id):
    if 'user_id' not in session:
        flash('Please log in to access the calender', 'warning')
        return redirect(url_for('login'))
    
    post = db.session.get(Post, post_id)
    user = db.session.get(User, session['user_id'])
    
    if not any(pu.user_id == user.id for pu in post.participants):
        flash('You must join the group to view the calender.', 'warning')
        return redirect(url_for('/'))
    
    if request.method == 'POST':
        # Schedule creation logic
        title = request.form['title']
        description = request.form['description']
        date_str = request.form['date']
        date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
        new_schedule = Schedule(title=title, description=description, date=date, post_id=post_id)
        db.session.add(new_schedule)
        db.session.commit()
        flash('Schedule created successfully!', 'success')
        return redirect(url_for('group_calender', post_id=post_id))
    
    schedules = Schedule.query.filter_by(post_id=post_id).order_by(Schedule.date).all()
    
    return render_template('group_calender.html', post=post, schedules=schedules)

@app.route('/group/<int:post_id>/studymode')
def studymode(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('studymode.html', username=session['username'], post_id=post_id)

@app.route('/group/<int:post_id>/videochat')
def videochat(post_id):
    if 'user_id' not in session:
        flash('Please log in to view your my_page', 'warning')
        return redirect(url_for('login'))
    username = request.args.get('username') or session.get('username') or 'Guest'
    return render_template('videochat.html',post_id=post_id,username=username)
    


socketio.on('connect')
def handle_connect():
    # 클라이언트가 연결될 때마다 현재 활성 사용자 목록을 전송
    emit('user_list', list(active_users.get(2, {}).keys()))

@socketio.on('join-time')
def on_join(data):
    username = data['username']
    post_id = data['postId']
    
    # 사용자가 없는 경우 추가
    if post_id not in active_users:
        active_users[post_id] = {}
    
    # 사용자 추가
    if username not in active_users[post_id]:
        active_users[post_id][username] = datetime.now()  # 시작 시간을 저장
    
    join_room(post_id)
    # 사용자 목록과 시작 시간을 클라이언트에 전송
    emit('user_list', {user: time.isoformat() for user, time in active_users[post_id].items()}, room=post_id)
    
@socketio.on('leave-time')
def on_leave(data):
    username = data['username']
    post_id = data['postId']

    if post_id in active_users and username in active_users[post_id]:
        start_time = active_users[post_id].pop(username)
        session_duration = (datetime.now() - start_time).total_seconds()
        
        # Update total study time in the database
        user = User.query.filter_by(username=username).first()
        post_user = PostUser.query.filter_by(post_id=post_id, user_id=user.id).first()
        if user:
            user.total_study_time += int(session_duration)
            db.session.commit()
        if post_user:
            post_user.study_time += int(session_duration)
            db.session.commit()
    
    # post_id가 active_users에 있는지 확인
    if post_id in active_users:
        if username in active_users[post_id]:
            del active_users[post_id][username]
        
        # 해당 post_id에 다른 사용자가 없으면 post_id 제거
        if not active_users[post_id]:
            del active_users[post_id]
    
    # 사용자 목록을 해당 post_id 룸에 전송
    emit('user_list', list(active_users.get(post_id, {}).keys()), room=post_id)

@app.route('/search_group')
def search_group():
 if 'user_id' not in session:
       flash('Please log in to access this page.', 'warning')
       return redirect(url_for('login')) 
 posts = Post.query.all()
 return render_template('search_group.html',posts=posts,logged_in=True)   

@app.route('/my_page')
def my_page():
    if 'user_id' not in session:
        flash('Please log in to view your my_page', 'warning')
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    joined_posts = user.joined_posts

    total_seconds = user.total_study_time
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    formatted_study_time = f"{hours}시간 {minutes}분 {seconds}초"

    return render_template('my_page.html', joined_posts=joined_posts, formatted_study_time=formatted_study_time)
#화상회의-----------------------------------------------------------------------------------------------------

app.config['SECRET_KEY'] = 'secret!'

ROOM = 'mesh_room'
users = {}  # sid -> user_id

@socketio.on('connect')
def handle_connect(auth):
    sid = request.sid
    print('Client connected:', sid, 'auth:', auth)

@socketio.on('join')
def handle_join(data):
    user_id = data['user_id']
    sid = request.sid
    users[sid] = user_id
    join_room(ROOM)
    # 기존 참가자에게 신규 참가 알림
    emit('new-user', {'user_id': user_id, 'sid': sid}, room=ROOM, include_self=False)
    # 신규 참가자에게 기존 참가자 목록 전달
    peers = [{'user_id': uid, 'sid': s} for s, uid in users.items() if s != sid]
    emit('all-users', {'peers': peers})

@socketio.on('offer')
def handle_offer(data):
    target = data['target_sid']
    sid    = request.sid
    # SDP offer와 발신자(sender) 정보를 같이 보냅니다
    emit('offer', {
        'sdp':    data['sdp'],
        'sender': sid
    }, room=target)

@socketio.on('answer')
def handle_answer(data):
    target = data['target_sid']
    sid    = request.sid
    # SDP answer와 발신자(sender) 정보를 같이 보냅니다
    emit('answer', {
        'sdp':    data['sdp'],
        'sender': sid
    }, room=target)

@socketio.on('ice-candidate')
def handle_ice(data):
    target = data['target_sid']
    sid    = request.sid
    # ICE 후보와 발신자(sender) 정보를 같이 보냅니다
    emit('ice-candidate', {
        'candidate': data['candidate'],
        'sender':    sid
    }, room=target)

@socketio.on('disconnect')
def handle_disconnect(sid=None):
    # sid가 넘어오지 않으면 request.sid 사용
    sid = sid or request.sid

    # users dict에서 제거
    user_id = users.pop(sid, None)

    # 룸에서 나가기 (sid 명시)
    leave_room(ROOM, sid=sid)

    # 모두에게 알림
    emit('user-disconnected', {'user_id': user_id, 'sid': sid}, room=ROOM)
    print('Client disconnected', sid)
#-----------화상비디오 채팅-----------
@socketio.on('chat_message')
def handle_chat_message(data):
    room = data.get('room')
    msg = data.get('msg')
    #user_id = data.get('user_id') or session.get('user_id')
    username = data.get('username') or 'Unknown'
  
    #user = User.query.get(user_id) if user_id else None
    #username = user.username if user else f"Guest-{user_id[:5]}"

    print(f"[chat_message] ({room}) {username}: {msg}")

    emit('chat_message', {
        'username': username,
        'msg': msg
    }, room=room)
#--해야할일 기능 알림구현---------------------------------------------------------------
@app.route('/api/todo_status/<int:post_id>')
def get_todo_status(post_id):
    # 퀴즈 개수 조회
    quiz_count = Quiz.query.filter_by(post_id=post_id).count()

    # 공유 자료 중 실제 파일이 있는 디렉토리 수 또는 파일 수 계산
    group_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(post_id))
    file_count = 0
    if os.path.exists(group_folder):
        for root, dirs, files in os.walk(group_folder):
            if len(files) > 0:
                file_count += len(files)  # 또는 file_count += 1 if just want directory count

    


    return jsonify({
        'quiz_count': quiz_count,
        'file_count': file_count,
        
    })



# 애플리케이션 실행
if __name__ == '__main__':   
    with app.app_context():
        db.create_all()  # 데이터베이스와 테이블을 초기화합니다.
    
    socketio.run(app, debug=True)
   
