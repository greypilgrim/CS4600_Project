from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os
from werkzeug.utils import secure_filename
from utils import encrypt_and_send, receive_and_decrypt, generate_keys

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'pem', 'txt', 'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['GET', 'POST'])
def generate_keys_page():
    if request.method == 'POST':
        # Generate two key pairs: one for the sender and one for the receiver
        sender_private_key = os.path.join(UPLOAD_FOLDER, 'sender_private_key.pem')
        sender_public_key = os.path.join(UPLOAD_FOLDER, 'sender_public_key.pem')
        receiver_private_key = os.path.join(UPLOAD_FOLDER, 'receiver_private_key.pem')
        receiver_public_key = os.path.join(UPLOAD_FOLDER, 'receiver_public_key.pem')

        generate_keys(sender_private_key, sender_public_key)
        generate_keys(receiver_private_key, receiver_public_key)

        flash('RSA key pairs generated successfully! You can download them below.')
        return render_template(
            'generate_keys.html',
            sender_private_key=sender_private_key,
            sender_public_key=sender_public_key,
            receiver_private_key=receiver_private_key,
            receiver_public_key=receiver_public_key
        )

    return render_template('generate_keys.html')

@app.route('/sender', methods=['GET', 'POST'])
def sender_page():
    if request.method == 'POST':
        pub_key_file = request.files.get('public_key')
        message = request.form.get('message')

        if not pub_key_file or not allowed_file(pub_key_file.filename):
            flash('Please upload a valid public key file.')
            return redirect(url_for('sender_page'))

        if not message:
            flash('Please enter a message to encrypt.')
            return redirect(url_for('sender_page'))

        pub_key_path = os.path.join(UPLOAD_FOLDER, secure_filename(pub_key_file.filename))
        pub_key_file.save(pub_key_path)

        output_file = os.path.join(UPLOAD_FOLDER, 'message_package.json')
        encrypt_and_send(pub_key_path, message, output_file)
        flash('Message encrypted successfully! You can download the encrypted file below.')
        return render_template('sender.html', download_link=output_file)

    return render_template('sender.html')

@app.route('/receiver', methods=['GET', 'POST'])
def receiver_page():
    decrypted_message = None
    if request.method == 'POST':
        priv_key_file = request.files.get('private_key')
        encrypted_file = request.files.get('encrypted_file')

        if not priv_key_file or not allowed_file(priv_key_file.filename):
            flash('Please upload a valid private key file.')
            return redirect(url_for('receiver_page'))

        if not encrypted_file or not allowed_file(encrypted_file.filename):
            flash('Please upload a valid encrypted file.')
            return redirect(url_for('receiver_page'))

        priv_key_path = os.path.join(UPLOAD_FOLDER, secure_filename(priv_key_file.filename))
        encrypted_file_path = os.path.join(UPLOAD_FOLDER, secure_filename(encrypted_file.filename))
        priv_key_file.save(priv_key_path)
        encrypted_file.save(encrypted_file_path)

        try:
            decrypted_message = receive_and_decrypt(priv_key_path, encrypted_file_path)
            flash('Message decrypted successfully!')
        except Exception as e:
            flash(f'Error during decryption: {str(e)}')

    return render_template('receiver.html', message=decrypted_message)

@app.route('/download/<path:filename>')
def download_file(filename):
    return send_file(filename, as_attachment=True)

@app.route('/demo')
def demo():
    return redirect(url_for('demo_step', step=1))

@app.route('/demo/step<int:step>', methods=['GET', 'POST'])
def demo_step(step):
    if step == 1:
        # Step 1: Generate RSA Keys
        sender_private_key = None
        sender_public_key = None
        receiver_private_key = None
        receiver_public_key = None

        if request.method == 'POST':
            sender_private_key_path = os.path.join(UPLOAD_FOLDER, 'sender_private_key.pem')
            sender_public_key_path = os.path.join(UPLOAD_FOLDER, 'sender_public_key.pem')
            receiver_private_key_path = os.path.join(UPLOAD_FOLDER, 'receiver_private_key.pem')
            receiver_public_key_path = os.path.join(UPLOAD_FOLDER, 'receiver_public_key.pem')

            generate_keys(sender_private_key_path, sender_public_key_path)
            generate_keys(receiver_private_key_path, receiver_public_key_path)

            # Read the generated keys to display them
            with open(sender_private_key_path) as f:
                sender_private_key = f.read()
            with open(sender_public_key_path) as f:
                sender_public_key = f.read()
            with open(receiver_private_key_path) as f:
                receiver_private_key = f.read()
            with open(receiver_public_key_path) as f:
                receiver_public_key = f.read()

        return render_template(
            'demo_step1.html',
            sender_private_key=sender_private_key,
            sender_public_key=sender_public_key,
            receiver_private_key=receiver_private_key,
            receiver_public_key=receiver_public_key
        )

    elif step == 2:
        # Step 2: Sender Encrypts a Message
        if request.method == 'POST':
            message = request.form.get('message')
            receiver_public_key = os.path.join(UPLOAD_FOLDER, 'receiver_public_key.pem')
            output_file = os.path.join(UPLOAD_FOLDER, 'message_package.json')

            encrypt_and_send(receiver_public_key, message, output_file)
            flash('Message encrypted and sent.')
            return redirect(url_for('demo_step', step=3))

        return render_template('demo_step2.html')

    elif step == 3:
        # Step 3: Receiver Decrypts the Message
        decrypted_message = None
        encrypted_data = None
        
        # Read encrypted data if it exists
        message_package_path = os.path.join(UPLOAD_FOLDER, 'message_package.json')
        if os.path.exists(message_package_path):
            with open(message_package_path) as f:
                encrypted_data = f.read()
                
        if request.method == 'POST':
            receiver_private_key = os.path.join(UPLOAD_FOLDER, 'receiver_private_key.pem')

            try:
                decrypted_message = receive_and_decrypt(receiver_private_key, message_package_path)
                flash('Message decrypted successfully!')
            except Exception as e:
                flash(f'Error during decryption: {str(e)}')

        return render_template('demo_step3.html', 
                              decrypted_message=decrypted_message, 
                              encrypted_data=encrypted_data)

    elif step == 4:
        # Step 4: Summary
        sender_public_key = None
        receiver_private_key = None
        encrypted_data = None
        
        # Read files if they exist
        sender_public_key_path = os.path.join(UPLOAD_FOLDER, 'sender_public_key.pem')
        receiver_private_key_path = os.path.join(UPLOAD_FOLDER, 'receiver_private_key.pem')
        message_package_path = os.path.join(UPLOAD_FOLDER, 'message_package.json')
        
        if os.path.exists(sender_public_key_path):
            with open(sender_public_key_path) as f:
                sender_public_key = f.read()
                
        if os.path.exists(receiver_private_key_path):
            with open(receiver_private_key_path) as f:
                receiver_private_key = f.read()
                
        if os.path.exists(message_package_path):
            with open(message_package_path) as f:
                encrypted_data = f.read()

        return render_template('demo_step4.html', 
                              sender_public_key=sender_public_key, 
                              receiver_private_key=receiver_private_key, 
                              encrypted_data=encrypted_data)

    else:
        return redirect(url_for('demo'))

if __name__ == '__main__':
    app.run(debug=True)
