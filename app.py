from flask import Flask, request, jsonify, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from fingerprint import Fingerprint
from flask_sse import sse
from geopy.distance import geodesic
from flask_socketio import SocketIO
from flask_cors import CORS

app = Flask(__name__)

# Configure MySQL database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://ejmpa:454500@localhost/iwallet_dummy_data'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)


loans = []
lenders = []

class Loan:
    def _init_(self, borrower, amount, term, rate):
        self.borrower = borrower
        self.amount = amount
        self.term = term
        self.rate = rate
        self.approved = False

class Lender:
    def _init_(self, name, available_funds, preferred_rate, max_loan_amount):
        self.name = name
        self.available_funds = available_funds
        self.preferred_rate = preferred_rate
        self.max_loan_amount = max_loan_amount

@app.route('/create_loan', methods=['POST'])
def create_loan():
    data = request.get_json()
    borrower = data['borrower']
    amount = data['amount']
    term = data['term']
    rate = data['rate']

    loan = Loan(borrower, amount, term, rate)
    loans.append(loan)

    return jsonify({'message': 'Loan request created successfully'})

@app.route('/approve_loan/<int:loan_id>', methods=['POST'])
def approve_loan(loan_id):
    loan = loans[loan_id]
    loan.approved = True

    return jsonify({'message': 'Loan approved successfully'})

@app.route('/create_lender', methods=['POST'])
def create_lender():
    data = request.get_json()
    name = data['name']
    available_funds = data['available_funds']
    preferred_rate = data['preferred_rate']
    max_loan_amount = data['max_loan_amount']

    lender = Lender(name, available_funds, preferred_rate, max_loan_amount)
    lenders.append(lender)

    return jsonify({'message': 'Lender profile created successfully'})

@app.route('/lenders', methods=['GET'])
def get_lenders():
    lender_data = [{'name': lender.name, 'available_funds': lender.available_funds, 'preferred_rate': lender.preferred_rate, 'max_loan_amount': lender.max_loan_amount} for lender in lenders]
    return jsonify({'lenders': lender_data})


# In-memory storage for messages
messages = []

# A dictionary to store users and their socket connections
user_sockets = {}

@app.route('/')
def index():
    return render_template('index.htm')

@socketio.on('connect')
def handle_connect():
    user_id = request.args.get('user_id')
    if user_id:
        user_sockets[user_id] = request.sid

@socketio.on('message')
def handle_message(data):
    recipient_id = data.get('recipient_id')
    message = data.get('message')

    if recipient_id in user_sockets:
        recipient_sid = user_sockets[recipient_id]
        socketio.emit('message', message, room=recipient_sid)
        socketio.emit('message', message, room=request.sid)
        messages.append({'from': request.sid, 'to': recipient_sid, 'message': message})

@socketio.on('get_messages')
def handle_get_messages(data):
    user_id = data.get('user_id')
    if user_id:
        user_messages = [msg['message'] for msg in messages if
                         msg['from'] == user_sockets.get(user_id) or msg['to'] == user_sockets.get(user_id)]
        socketio.emit('messages', user_messages, room=request.sid)


# In-memory storage for user feedback
feedback_data = []

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    data = request.get_json()
    username = data['username']
    feedback = data['feedback']

    # Store the feedback in memory (use a database)
    feedback_data.append({'username': username, 'feedback': feedback})

    return jsonify({'message': 'Feedback submitted successfully'})

@app.route('/get_feedback', methods=['GET'])
def get_feedback():
    return jsonify({'feedback': feedback_data})


# In-memory storage for user accounts, referrals, and rewards
users = {}
referral_rewards = {}
agent_rewards = {}

@app.route('/refer', methods=['POST'])
def refer():
    data = request.get_json()
    referrer = data['referrer']
    referee = data['referee']

    if referrer in users and referee in users:
        if users[referrer]['referred_by'] is None:
            users[referrer]['referred_users'].append(referee)
            users[referee]['referred_by'] = referrer

            # Reward the referrer 
            referral_rewards[referrer] += 10

            return jsonify({'message': 'Referral successful'})
        return jsonify({'message': 'Referrer has already referred a user'})
    return jsonify({'message': 'Referral failed'})

@app.route('/get_referral_rewards/<username>', methods=['GET'])
def get_referral_rewards(username):
    if username in referral_rewards:
        return jsonify({'referral_rewards': referral_rewards[username]})
    return jsonify({'message': 'User not found'})

@app.route('/get_referred_users/<username>', methods=['GET'])
def get_referred_users(username):
    if username in users:
        return jsonify({'referred_users': users[username]['referred_users']})
    return jsonify({'message': 'User not found'})

@app.route('/add_agent_reward', methods=['POST'])
def add_agent_reward():
    data = request.get_json()
    agent = data['agent']
    reward_amount = data['reward_amount']

    if agent in users:
        agent_rewards[agent] = agent_rewards.get(agent, 0) + reward_amount
        return jsonify({'message': 'Agent reward added successfully'})
    return jsonify({'message': 'Agent not found'})

@app.route('/get_agent_rewards/<agent>', methods=['GET'])
def get_agent_rewards(agent):
    if agent in agent_rewards:
        return jsonify({'agent_rewards': agent_rewards[agent]})
    return jsonify({'message': 'Agent not found'})

# Dummy data for user and agent locations
users = [{'id': 1, 'location': (40.7128, -74.0060)}]
agents = [{'id': 101, 'location': (40.7128, -74.0050)}]

# Function to find nearby agents based on user location
def find_nearby_agents(user_location):
    nearby_agents = []
    for agent in agents:
        distance = geodesic(user_location, agent['location']).kilometers
        if distance < 1:  # Adjust the distance threshold as needed
            nearby_agents.append(agent)
    return nearby_agents

@app.route('/find_nearby_agents', methods=['GET'])
def get_nearby_agents():
    user_id = int(request.args.get('user_id'))
    user = next((u for u in users if u['id'] == user_id), None)
    if user:
        nearby_agents = find_nearby_agents(user['location'])
        return jsonify({'nearby_agents': nearby_agents})
    else:
        return jsonify({'message': 'User not found'}, 404)
    

#Route for user location update
@app.route('/update/user_location/<int:user_id>', methods=['PUT'])
def update_user_location(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}, 404)

    data = request.get_json()
    user.latitude = data['latitude']
    user.longitude = data['longitude']
    db.session.commit()
    return jsonify({'message': 'User location updated successfully'})

# Route for agent location update
@app.route('/update/agent_location/<int:agent_id>', methods=['PUT'])
def update_agent_location(agent_id):
    agent = Agent.query.get(agent_id)
    if not agent:
        return jsonify({'message': 'Agent not found'}, 404)

    data = request.get_json()
    agent.latitude = data['latitude']
    agent.longitude = data['longitude']
    db.session.commit()
    return jsonify({'message': 'Agent location updated successfully'})

# Route for agent registration
@app.route('/register/agent', methods=['POST'])
def register_agent():
    data = request.get_json()
    new_agent = Agent(username=data['username'], latitude=data['latitude'], longitude=data['longitude'])
    db.session.add(new_agent)
    db.session.commit()
    return jsonify({'message': 'Agent registered successfully'})

# Create a User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80, collation='utf8_general_ci'), unique=True, nullable=False)
    password = db.Column(db.String(120, collation='utf8_general_ci'), nullable=False)
    bvn = db.Column(db.String(10, collation='utf8_general_ci'))  # BVN field
    live_picture = db.Column(db.Text(collation='utf8_general_ci'))  # Store as TEXT
    fingerprint = db.Column(db.Text(collation='utf8_general_ci'))  # Store as TEXT

# Create a decorator for authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        except Exception:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Route for user registration and biometric data
@app.route('/register_with_biometrics', methods=['POST'])
def register_with_biometrics():
    data = request.get_json()
    users[username] = {'referral_code': username, 'referred_by': None, 'referred_users': []}
    referral_rewards[username] = 0
    return jsonify

    new_user = User(username=data['username'], latitude=data['latitude'], longitude=data['longitude'])
    db.session.add(new_user)
    db.session.commit()
    bvn = data.get('bvn')
    live_picture_base64 = data.get('live_picture')
    fingerprint_base64 = data.get('fingerprint')

    # Verify the user by BVN
    user = User.query.filter_by(bvn=bvn).first()
    if not user:
        return jsonify({'message': 'User with this BVN not found'})

    # Store the biometric data
    user.live_picture = live_picture_base64
    user.fingerprint = fingerprint_base64
    db.session.commit()

    return jsonify({'message': 'Biometric data saved for user'})

# Route for retrieving and verifying biometric data
@app.route('/verify_biometrics/<string:bvn>', methods=['POST'])
def verify_biometrics(bvn):
    data = request.get_json()
    live_picture_base64 = data.get('live_picture')
    fingerprint_base64 = data.get('fingerprint')

    # Retrieve the user by BVN
    user = User.query.filter_by(bvn=bvn).first()
    if not user:
        return jsonify({'message': 'User with this BVN not found'})

# Initialize the fingerprint reader
fingerprint_reader = Fingerprint()
#Function to verify fingerprint
def verify_fingerprint(stored_template, provided_template):
    return fingerprint_reader.verify(stored_template, provided_template)


    # Verify the live picture and fingerprint
    if (
        user.live_picture == live_picture_base64
        and user.fingerprint == fingerprint_base64
    ):
        return jsonify({'message': 'Biometric verification successful'})
    else:
        return jsonify({'message': 'Biometric verification failed'})

# Function to retrieve the stored fingerprint template for a user
def get_fingerprint_template(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return user.fingerprint_template
    return None

# Function to retrieve the stored fingerprint template for a user 
# Route for user login with password or fingerprint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    auth_type = data.get('auth_type')  # 'password' or 'fingerprint'

    if auth_type not in ['password', 'fingerprint']:
        return jsonify({'message': 'Invalid authentication type'})

    if auth_type == 'password':
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
        user = User.query.filter_by(username=auth.username).first()
        if not user:
            return jsonify({'message': 'User not found'})
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                               app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})
        return jsonify({'message': 'Password is incorrect'})
    elif auth_type == 'fingerprint':
        # Implement fingerprint authentication logic here
    
    # Function to retrieve the stored fingerprint template for a user
        def get_fingerprint_template(username):
            user = User.query.filter_by(username=username).first()
            if user:
                return user.fingerprint_template
            return None

# Route to retrieve the stored fingerprint template for a user
@app.route('/get_fingerprint_template/<string:username>', methods=['GET'])
def retrieve_fingerprint_template(username):
    fingerprint_template = get_fingerprint_template(username)
    if fingerprint_template:
        return jsonify({'fingerprint_template': fingerprint_template})
    else:
        return jsonify({'message': 'Fingerprint template not found'})
    
    # You need to retrieve the user's stored fingerprint template from the database
        user = User.query.filter_by(username=data.get('username')).first()
        if user and user.fingerprint:
            stored_template = user.fingerprint
            provided_template = data.get('fingerprint_template')  # Template obtained from the fingerprint device
            if verify_fingerprint(stored_template, provided_template):
                token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                                   app.config['SECRET_KEY'])
                return jsonify({'token': token.decode('UTF-8')})
        return jsonify({'message': 'Fingerprint authentication failed'})

        # You'll need to verify the provided fingerprint data against stored fingerprint data
        # If the fingerprint is valid, generate a token and return it



# Create a model for disputes
class Dispute(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Status can be 'Pending', 'In Progress', or 'Resolved'


def categorize_dispute(sender, receiver, text):
    if "payment" in text:
        return "Payment Dispute"
    if "interest rate" in text:
        return "Interest Rate Dispute"
    if "loan approval" in text:
        return "Loan Approval Dispute"
    if "repayment terms" in text:
        return "Repayment Terms Dispute"
    return "Other"

@app.route('/analyze_dispute', methods=['POST'])
def analyze_dispute():
    data = request.get_json()
    sender = data['sender']
    receiver = data['receiver']
    dispute_text = data['dispute_text']

    category = categorize_dispute(sender, receiver, dispute_text)

    return jsonify({'category': category})


# API endpoint to submit a dispute
@app.route('/submit_dispute', methods=['POST'])
def submit_dispute():
    data = request.get_json()
    user_id = data['user_id']
    category = data['category']
    description = data['description']

    dispute = Dispute(user_id=user_id, category=category, description=description)
    db.session.add(dispute)
    db.session.commit()
    return jsonify({'message': 'Dispute submitted successfully'})

# API endpoint to get a list of disputes
@app.route('/disputes', methods=['GET'])
def get_disputes():
    disputes = Dispute.query.all()
    dispute_list = []
    for dispute in disputes:
        dispute_list.append({
            'id': dispute.id,
            'user_id': dispute.user_id,
            'category': dispute.category,
            'description': dispute.description,
            'status': dispute.status
        })
    return jsonify({'disputes': dispute_list})

# API endpoint to update the status of a dispute
@app.route('/update_status/<int:dispute_id>', methods=['PUT'])
def update_dispute_status(dispute_id):
    data = request.get_json()
    status = data['status']
    dispute = Dispute.query.get(dispute_id)
    if dispute:
        dispute.status = status
        db.session.commit()
        return jsonify({'message': 'Dispute status updated successfully'})
    return jsonify({'message': 'Dispute not found'}, 404)

    sse.init_app(app)


# Reviews

users = {}

@app.route('/rate_user', methods=['POST'])
def rate_user():
    data = request.get_json()
    rater = data['rater']
    target = data['target']
    rating = data['rating']
    review = data['review']

    if target in users:
        users[target]['reviews'].append({'rater': rater, 'rating': rating, 'review': review})
        return jsonify({'message': 'User rated and reviewed successfully'})
    return jsonify({'message': 'User not found'})

@app.route('/get_reviews/<username>', methods=['GET'])
def get_reviews(username):
    if username in users:
        reviews = users[username]['reviews']
        return jsonify({'reviews': reviews})
    return jsonify({'message': 'User not found'})



# Tansactions
@app.route('/balance/<username>', methods=['GET'])
def get_balance(username):
    if username in users:
        return jsonify({'balance': users[username]['balance']})
    return jsonify({'message': 'User not found'})

@app.route('/transfer', methods=['POST'])
def transfer_funds():
    data = request.get_json()
    sender = data['sender']
    receiver = data['receiver']
    amount = data['amount']

    if sender in users and receiver in users and users[sender]['balance'] >= amount:
        users[sender]['balance'] -= amount
        users[receiver]['balance'] += amount

        # Update transaction history for both sender and receiver
        users[sender]['transactions'].append(f'Sent {amount} to {receiver}')
        users[receiver]['transactions'].append(f'Received {amount} from {sender}')

        return jsonify({'message': 'Funds transferred successfully'})
    return jsonify({'message': 'Transfer failed'})

@app.route('/transaction_history/<username>', methods=['GET'])
def get_transaction_history(username):
    if username in users:
        history = users[username]['transactions']
        return jsonify({'transaction_history': history})
    return jsonify({'message': 'User not found'})

@app.route('/generate_receipt/<username>', methods=['GET'])
def generate_receipt(username):
    if username in users:
        # Retrieve the user's transaction history
        history = users[username]['transactions']

        # Create a receipt with transaction details
        receipt = f"Transaction Receipt for {username}\n"
        receipt += "\n".join(history)

        # You can save this receipt to a file or provide it as a response
        return receipt
    return jsonify({'message': 'User not found'})


# FAQ
from flask import render_template

@app.route('/faq', methods=['GET'])
def faq():
    # Load FAQ data from a database or a configuration file
    faq_data = get_faq_data()  # Implement this function
    return render_template('faq.html', faq_data=faq_data)

# Create a model for support tickets
class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')  # Status can be 'Open', 'In Progress', or 'Closed'

# Create a route for users to submit support tickets
@app.route('/submit_ticket', methods=['GET', 'POST'])
def submit_ticket():
    if request.method == 'POST':
        user_id = current_user.id  # You need to implement user authentication
        subject = request.form['subject']
        description = request.form['description']

        support_ticket = SupportTicket(user_id=user_id, subject=subject, description=description)
        db.session.add(support_ticket)
        db.session.commit()
        return redirect('/support_tickets')
    return render_template('index.htm')

# Create a route to view and manage support tickets
@app.route('/support_tickets', methods=['GET'])
def support_tickets():
    # Fetch support tickets for the current user (if logged in)
    if current_user.is_authenticated:
        user_id = current_user.id
        user_tickets = SupportTicket.query.filter_by(user_id=user_id).all()
    else:
        user_tickets = []

    
    return render_template('support_tickets.html', user_tickets=user_tickets)



# Initialize database with app context
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
