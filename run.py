from flask_socketio import SocketIO, emit
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
        return filename
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



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    last_accessed = db.Column(db.DateTime, nullable=True)
    joined_posts = db.relationship('PostUser', back_populates='user')

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

    
class PostUser(db.Model):
    __tablename__ = 'post_user'
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    role = db.Column(db.String(20), default='member')
    post = db.relationship('Post', back_populates='participants')
    user = db.relationship('User', back_populates='joined_posts')

    def __repr__(self):
        return f"PostUser('{self.post_id}', '{self.user_id}', '{self.role}')"
    
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

@socketio.on('chat_message')
def handle_chat_message(data):
    emit('chat_message', data, broadcast=True)

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

@app.route('/group/<int:post_id>/chat', methods=['GET', 'POST'])
def group_chat(post_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    post = db.session.get(Post, post_id)
    return render_template('group_chat.html', post=post, logged_in=True)

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
    return send_from_directory(group_folder, filename, as_attachment=True)

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
    return render_template('my_page.html', joined_posts=joined_posts)


# 애플리케이션 실행
if __name__ == '__main__':   
    with app.app_context():
        db.create_all()  # 데이터베이스와 테이블을 초기화합니다.
    app.run(debug=True)
    socketio.run(app, debug=True)
   

