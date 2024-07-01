from flask import Flask, request, jsonify, render_template, request, redirect, url_for, flash, make_response, session, send_from_directory
from flask_paginate import Pagination, get_page_args
import mysql.connector
from mysql.connector import pooling
from datetime import datetime, timedelta
import random
import string
import uuid
import os
from collections import OrderedDict
from flasgger import Swagger
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
#from flask import safe_join, send_from_directory

app = Flask(__name__)
app.config['SWAGGER'] = {
    'title': 'My API',
    'swagger:': 3.0
}
app.config['SECRET_KEY'] = "sua_chave_secreta_aleatoria_aqui"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)

swagger = Swagger(app)


base_directory = os.path.abspath(os.path.dirname(__file__))  # Obtém o caminho do diretório onde o script está rodando
uploads_directory = os.path.join(base_directory, 'uploads')
images_directory = os.path.join(uploads_directory, 'images')
bundles_directory = os.path.join(uploads_directory, 'bundles')

os.makedirs(images_directory, exist_ok=True)
os.makedirs(bundles_directory, exist_ok=True)
# Configuração do pool de conexões

# Configuração da conexão com o banco de dados MySQL
db_config = {
    'host': "pmleandb.mysql.dbaas.com.br",
    'user': "pmleandb",
    'password': "C#PMLean2020",
    'database': "pmleandb"
}

db_pool = pooling.MySQLConnectionPool(
    pool_name="my_pool",
    pool_size=5,
    **db_config
)


##################################################Site##########################################################
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    # Aqui você deveria buscar no banco se o usuário realmente existe
    # E retornar None se não existir
    db = mysql.connector.connect(**db_config)
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM TB_LOGIN_VM WHERE LoginVMID = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    db.close()
    if user_data:
        return User(user_id)
    return None

# Helpers
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_file(file, directory):
    filename = secure_filename(file.filename)
    filepath = os.path.join(directory, filename)
    file.save(filepath)
    return filepath

# Routes
@app.route('/')
def home():
    return redirect(url_for('index'))

@app.route('/index')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    response = make_response(render_template('login.html'))
    response.headers["Cache-Control"] = "no-store"
    session.permanent = True
    return response


@app.route('/dashboard')
@login_required
def dashboard():
    db = db_pool.get_connection()
    cursor = db.cursor(dictionary=True)
    login_vmid = current_user.id
    cursor.execute("""
        SELECT s.*, i.image_path FROM TB_SCENE s
        LEFT JOIN TB_SCENE_IMAGES i ON s.scene_id = i.scene_id
        WHERE s.is_public = 1 OR (s.is_public = 0 AND s.LoginVMID = %s)
    """, (login_vmid,))
    cenarios = cursor.fetchall()
    db.close()
    # Processar caminho das imagens para obter apenas o nome do arquivo
    for cenario in cenarios:
        image_path = cenario.get('image_path')  # Uso de .get() para evitar KeyError
        if image_path:
            cenario['image_path'] = os.path.basename(image_path)

    return render_template('dashboard.html', cenarios=cenarios)

@app.route('/uploads/images/<path:filename>')
def send_image(filename):
    return send_from_directory(images_directory, filename)

@app.route('/download_bundle/<filename>')
@login_required
def download_bundle(filename):
    directory = bundles_directory  # Certifique-se de que este é o caminho correto para onde os bundles são salvos
    try:
        return send_from_directory(directory, filename, as_attachment=True)
    except FileNotFoundError:
        flash('Arquivo não encontrado.', 'error')
        return redirect(url_for('dashboard'))



@app.route('/cadastrar-cenarios')
@login_required
def cadastrar_cenarios():
    return render_template('cadastrar_cenarios.html')

def secure_filename_with_timestamp(filename):
    base, ext = os.path.splitext(filename)
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{base}_{timestamp}{ext}"

@app.route('/enviar-cenario', methods=['POST'])
@login_required
def enviar_cenario():
    name = request.form['scenarioName']
    description = request.form['description']
    tags = request.form['tags']
    is_public = request.form['visibilityOption'] == 'public'
    login_vmid = current_user.id  # Assume que current_user.id é o LoginVMID

    # Definição dos diretórios para salvar imagens e bundles
    base_directory = os.path.abspath(os.path.dirname(__file__))
    uploads_directory = os.path.join(base_directory, 'uploads')
    images_directory = os.path.join(uploads_directory, 'images')
    bundles_directory = os.path.join(uploads_directory, 'bundles')

    # Cria os diretórios se não existirem
    os.makedirs(images_directory, exist_ok=True)
    os.makedirs(bundles_directory, exist_ok=True)

    # Conexão com o banco para obter o versionName mais novo e inserir os dados
    db = db_pool.get_connection()
    cursor = db.cursor()

    try:
        # Obter o versionName mais recente
        cursor.execute("SELECT versionName FROM TB_VR_VERSION ORDER BY STR_TO_DATE(SUBSTRING(versionName, 1, 10), '%Y.%m.%d') DESC LIMIT 1")
        version_info = cursor.fetchone()
        version_name = version_info[0] if version_info else None

        if not version_name:
            flash('Não foi possível encontrar uma versão válida.', 'error')
            return redirect(url_for('cadastrar_cenarios'))

        # Inserir novo cenário com versionName
        cursor.execute(
            "INSERT INTO TB_SCENE (name, description, tags, is_public, LoginVMID, versionName) VALUES (%s, %s, %s, %s, %s, %s)",
            (name, description, tags, is_public, login_vmid, version_name)
        )
        db.commit()
        scene_id = cursor.lastrowid  # ID do cenário inserido

        # Processar e salvar arquivos de imagem
        if 'images' in request.files:
            for file in request.files.getlist('images'):
                if file and allowed_file(file.filename, {'png', 'jpg', 'jpeg', 'gif'}):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(images_directory, filename)
                    file.save(file_path)
                    cursor.execute(
                        "INSERT INTO TB_SCENE_IMAGES (scene_id, image_path) VALUES (%s, %s)",
                        (scene_id, file_path)
                    )
                    db.commit()

        # Processar e salvar Asset Bundles
        platforms = {'androidBundle': 'Android', 'windowsBundle': 'Windows', 'macBundle': 'Mac'}
        for key, platform in platforms.items():
            if key in request.files and allowed_file(request.files[key].filename, {'unity3d', 'assetbundle', 'bundle'}):
                filename = secure_filename(request.files[key].filename)
                bundle_path = os.path.join(bundles_directory, filename)
                request.files[key].save(bundle_path)
                cursor.execute(
                    "INSERT INTO TB_SCENE_BUNDLES (scene_id, platform, bundle_path) VALUES (%s, %s, %s)",
                    (scene_id, platform, bundle_path)
                )
                db.commit()

    except Exception as e:
        db.rollback()
        flash('Erro ao registrar cenário: {}'.format(str(e)), 'error')
        return redirect(url_for('cadastrar_cenarios'))
    finally:
        cursor.close()
        db.close()

    flash('Cenário cadastrado com sucesso!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/detalhes-cenario/<int:scene_id>')
@login_required
def detalhes_cenario(scene_id):
    db = db_pool.get_connection()
    cursor = db.cursor(dictionary=True)
    
    # Consulta para obter o cenário junto com o caminho da imagem usando LEFT JOIN
    cursor.execute("""
        SELECT s.*, i.image_path FROM TB_SCENE s
        LEFT JOIN TB_SCENE_IMAGES i ON s.scene_id = i.scene_id
        WHERE s.scene_id = %s
    """, (scene_id,))
    cenario = cursor.fetchone()
    
    # Processa o caminho da imagem para obter apenas o nome do arquivo
    if cenario and cenario.get('image_path'):
        cenario['image_path'] = os.path.basename(cenario['image_path'])

    # Busca os bundles associados ao cenário
    cursor.execute("SELECT * FROM TB_SCENE_BUNDLES WHERE scene_id = %s", (scene_id,))
    bundles = cursor.fetchall()
    db.close()

    # Debug para ver o conteúdo de bundles e cenário
    print("Cenário:", cenario)
    print("Bundles:", bundles)

    return render_template('detalhes_cenario.html', cenario=cenario, bundles=bundles)


@app.route('/editar-cenario/<int:scene_id>', methods=['GET', 'POST'])
@login_required
def editar_cenario(scene_id):
    db = db_pool.get_connection()
    cursor = db.cursor(dictionary=True)

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        tags = request.form['tags']
        cursor.execute("UPDATE TB_SCENE SET name=%s, description=%s, tags=%s WHERE scene_id=%s",
                       (name, description, tags, scene_id))
        db.commit()
        db.close()
        flash('Cenário atualizado com sucesso!', 'success')
        return redirect(url_for('dashboard'))

    # Se for GET, mostra o formulário com dados existentes
    cursor.execute("SELECT * FROM TB_SCENE WHERE scene_id = %s", (scene_id,))
    cenario = cursor.fetchone()
    db.close()
    return render_template('editar_cenario.html', cenario=cenario)

@app.route('/excluir-cenario/<int:scene_id>', methods=['POST'])
@login_required
def excluir_cenario(scene_id):
    db = db_pool.get_connection()
    cursor = db.cursor()
    cursor.execute("DELETE FROM TB_SCENE_BUNDLES WHERE scene_id = %s", (scene_id,))
    cursor.execute("DELETE FROM TB_SCENE_IMAGES WHERE scene_id = %s", (scene_id,))
    cursor.execute("DELETE FROM TB_SCENE WHERE scene_id = %s", (scene_id,))
    db.commit()
    db.close()
    flash('Cenário excluído com sucesso!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/auth/login', methods=['POST'])
def auth_login():
    username = request.form['username']
    password = request.form['password']

    db = mysql.connector.connect(**db_config)
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT LoginVMID FROM TB_LOGIN_VM WHERE UserName = %s AND Password = %s", (username, password))
        user_data = cursor.fetchone()
        if not user_data:
            flash('Usuário ou senha inválidos', 'error')
            return redirect(url_for('index'))
        user = User(user_data['LoginVMID'])
        login_user(user)
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('Erro ao fazer login', 'error')
        return redirect(url_for('index'))
    finally:
        cursor.close()
        db.close()

@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    session.clear()
    flash('Deslogado com sucesso!', 'success')
    return redirect(url_for('index'))

@app.after_request
def apply_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response
##################################################Site##########################################################


@app.route('/gerar_token', methods=['POST'])
def gerar_token():
    try:
        # Obtenha os dados do POST
        login = request.json['login']

        while True:
            # Gere um token alfanumérico de até 6 caracteres com letras maiúsculas e dígitos
            token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

            # Crie uma nova conexão com o banco de dados
            db = mysql.connector.connect(**db_config)
            cursor = db.cursor()

            # Consulte a tabela TB_LOGIN_TOKEN para verificar se o token já existe
            cursor.execute("SELECT COUNT(*) FROM TB_LOGIN_TOKEN WHERE token = %s", (token,))
            count = cursor.fetchone()[0]

            # Feche o cursor e a conexão com o banco de dados
            cursor.close()
            db.close()

            if count == 0:
                break

        # Crie uma nova conexão com o banco de dados para inserir os dados
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()

        # Consulte a tabela TB_LOGIN_VM para verificar se o nome existe
        cursor.execute("SELECT COUNT(*) FROM TB_LOGIN_VM WHERE UserName = %s", (login,))

        # Obtenha o resultado da contagem
        count = cursor.fetchone()[0]

        # Defina a data de validade com base na verificação do nome na tabela TB_LOGIN_VM
        if count > 0:
            data_validade = datetime.now() + timedelta(days=1)
        else:
            data_validade = datetime.now() + timedelta(hours=1)

        # Gere um UUID único sem traços
        unique_uuid = str(uuid.uuid4()).replace('-', '')

        # Insira os dados na tabela, incluindo o UUID
        cursor.execute("INSERT INTO TB_LOGIN_TOKEN (login, token, data_validade, UUID) VALUES (%s, %s, %s, %s)",
                       (login, token, data_validade, unique_uuid))

        # Faça commit das alterações
        db.commit()

        # Obtenha o ID autoincremento da última inserção
        cursor.execute("SELECT MAX(ID) FROM TB_LOGIN_TOKEN")

        # Obtém o ID inserido
        id = cursor.fetchone()[0]

        # Feche o cursor e a conexão com o banco de dados
        cursor.close()
        db.close()

        # Retorne os dados em formato JSON, incluindo o UUID
        return jsonify(
            {'id': id, 'login': login, 'token': token, 'data_validade': data_validade.strftime('%Y-%m-%d %H:%M:%S'),
             'UUID': unique_uuid})

    except Exception as e:
        # Em caso de erro, faça rollback e retorne uma mensagem de erro
        db.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/consultar_token/<string:token>', methods=['GET'])
def consultar_token(token):
    try:
        # Crie uma nova conexão com o banco de dados
        db = mysql.connector.connect(**db_config)

        # Crie um cursor para interagir com o banco de dados
        cursor = db.cursor()

        # Consulte a tabela TB_LOGIN_TOKEN para obter os registros onde a data de validade não tenha vencido
        cursor.execute(
            "SELECT id, login, token, data_validade, UUID FROM TB_LOGIN_TOKEN WHERE token = %s AND data_validade > NOW()",
            (token,))

        # Obtenha o primeiro resultado da consulta
        row = cursor.fetchone()

        # Feche o cursor e a conexão com o banco de dados
        cursor.close()
        db.close()

        # Se não houver resultado, retorne uma resposta 404
        if not row:
            return jsonify({'message': 'O token do usuário venceu'}), 404

        # Retorne o resultado encontrado em formato JSON sem os colchetes
        id, login, token, data_validade, unique_uuid = row
        return jsonify(
            {'id': id, 'login': login, 'token': token, 'data_validade': data_validade.strftime('%Y-%m-%d %H:%M:%S'),
             'UUID': unique_uuid})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/consultar_login/<string:login>', methods=['GET'])
def consultar_login(login):
    try:
        # Crie uma nova conexão com o banco de dados
        db = mysql.connector.connect(**db_config)

        # Crie um cursor para interagir com o banco de dados
        cursor = db.cursor()

        # Consulte a tabela TB_LOGIN_TOKEN para obter os registros onde a data de validade não tenha vencido
        cursor.execute(
            "SELECT id, login, token, data_validade, UUID FROM TB_LOGIN_TOKEN WHERE login = %s AND data_validade > NOW()",
            (login,))

        # Obtenha o primeiro resultado da consulta
        row = cursor.fetchone()

        # Feche o cursor e a conexão com o banco de dados
        cursor.close()
        db.close()

        # Se não houver resultado, retorne uma resposta 404
        if not row:
            return jsonify({'message': 'O token do usuário venceu'}), 404

        # Retorne o resultado encontrado em formato JSON sem os colchetes
        id, login, token, data_validade, unique_uuid = row
        return jsonify(
            {'id': id, 'login': login, 'token': token, 'data_validade': data_validade.strftime('%Y-%m-%d %H:%M:%S'),
             'UUID': unique_uuid})

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/login', methods=['POST'])
def login():
    dados = request.json
    username = dados['UserName']
    password = dados['Password']

    db = mysql.connector.connect(**db_config)
    cursor = db.cursor()

    try:
        # Verifica se o usuário existe na TB_LOGIN_VM
        cursor.execute("SELECT COUNT(*) FROM TB_LOGIN_VM WHERE UserName = %s AND Password = %s", (username, password))
        if cursor.fetchone()[0] == 0:
            return jsonify({'error': 'Usuário ou senha inválidos'}), 401

        # Verifica a última sessão na TB_LOGIN_SECTION
        cursor.execute("SELECT UUID, DataValidade FROM TB_LOGIN_SECTION WHERE UserName = %s ORDER BY ID DESC LIMIT 1",
                       (username,))
        result = cursor.fetchone()

        if result and result[1] > datetime.now():
            # Sessão ainda válida
            return jsonify(
                {'UserName': username, 'Token': result[0], 'DataValidade': result[1].strftime('%Y-%m-%d %H:%M:%S')})

        # Cria nova sessão
        new_uuid = str(uuid.uuid4())
        data_validade = datetime.now() + timedelta(days=1)
        cursor.execute("INSERT INTO TB_LOGIN_SECTION (UserName, UUID, DataValidade) VALUES (%s, %s, %s)",
                       (username, new_uuid, data_validade))
        db.commit()

        return jsonify(
            {'UserName': username, 'Token': new_uuid, 'DataValidade': data_validade.strftime('%Y-%m-%d %H:%M:%S')})

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/VerificaTokenLogin/<token>', methods=['GET'])
def verifica_token_login(token):
    db = mysql.connector.connect(**db_config)
    cursor = db.cursor()

    try:
        # Verifica se o token existe e está válido na TB_LOGIN_SECTION
        cursor.execute("SELECT DataValidade FROM TB_LOGIN_SECTION WHERE UUID = %s", (token,))
        result = cursor.fetchone()

        # Caso o resultado não seja encontrado
        if not result:
            return jsonify({'message': 'Token inválido ou não encontrado'}), 404

        # Caso o resultado seja menor que a datetime do momento da solicitação
        data_validade = result[0]
        if data_validade < datetime.now():
            # Token expirado
            return jsonify({'message': 'O login do usuário expirou'}), 401

        # Token válido
        return jsonify({'message': 'Token válido'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

##################################################AVATAR#########################################
class ProfileData:
    def __init__(self, data):
        #self.UserID = data['UserID']   ---- ESSA POHA ERA AUTOINCREMENT, TAVA DANDO ERRO
        self.LoginVRID = data['LoginVRID']
        self.AvatarURL = data['AvatarURL']
        self.Gender = data['Gender']
        self.HairIndex = data['HairIndex']
        self.BarbaIndex = data['BarbaIndex']
        self.EyeColorIndex = data['EyeColorIndex']
        self.SkinColorIndex = data['SkinColorIndex']
        self.ClothIndex = data['ClothIndex']
        self.ColorR = data['ColorR']
        self.ColorG = data['ColorG']
        self.ColorB = data['ColorB']
        self.ColorA = data['ColorA']

@app.route('/Avatar', methods=['POST'])
def create_avatar():
    try:
        data = request.json
        profile = ProfileData(data)

        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()

        insert_query = """
        INSERT INTO TB_VR_USER_PROFILE
        (Gender, HairIndex, BarbaIndex, EyeColorIndex, SkinColorIndex, ClothIndex, ColorR, ColorG, ColorB, ColorA, LoginVRID, AvatarURL)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (profile.Gender, profile.HairIndex, profile.BarbaIndex, profile.EyeColorIndex,
                                      profile.SkinColorIndex, profile.ClothIndex, profile.ColorR, profile.ColorG, profile.ColorB,
                                      profile.ColorA, profile.LoginVRID, profile.AvatarURL))

        db.commit()

        # Você pode recuperar o UserID gerado automaticamente se necessário
        user_id = cursor.lastrowid

        cursor.close()
        db.close()

        return jsonify({'message': 'Avatar criado com sucesso!', 'UserID': user_id}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/Avatar', methods=['GET'])
def get_avatar():
    try:
        # Recebe o parâmetro LoginVRID da URL
        login_vrid = request.args.get('LoginVRID')

        # Verifica se o LoginVRID foi fornecido
        if not login_vrid:
            return jsonify({'error': 'LoginVRID é necessário'}), 400

        # Cria uma nova conexão com o banco de dados
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(dictionary=True)

        # Consulta para buscar o perfil com base no LoginVRID
        query = """
        SELECT UserID, LoginVRID, AvatarURL, Gender, HairIndex, BarbaIndex, EyeColorIndex, SkinColorIndex, ClothIndex, ColorR, ColorG, ColorB, ColorA
        FROM TB_VR_USER_PROFILE
        WHERE LoginVRID = %s
        """
        cursor.execute(query, (login_vrid,))

        # Obtém o primeiro resultado da consulta
        profile_data = cursor.fetchone()

        # Fecha o cursor e a conexão
        cursor.close()
        db.close()

        # Se o perfil não for encontrado
        if not profile_data:
            return jsonify({'message': 'Perfil não encontrado para o LoginVRID fornecido'}), 404

        # Retorna os dados do perfil
        return jsonify(profile_data)

    except Exception as e:
        # Em caso de erro, retorna uma mensagem de erro
        return jsonify({'error': str(e)}), 500

#########################################LOGINVM############################################

@app.route('/LoginVM', methods=['GET'])
def login_vm():
    try:
        # Recebe os parâmetros UserName e Password da URL
        username = request.args.get('UserName')
        password = request.args.get('Password')

        # Verifica se UserName e Password foram fornecidos
        if not username or not password:
            return jsonify({'error': 'UserName e Password são necessários'}), 400

        # Cria uma nova conexão com o banco de dados
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(dictionary=True)

        # Consulta para verificar se o UserName e Password correspondem
        query = """
        SELECT LoginVMID, UserName, Name, Password, AffiliateKey, AffiliateKeyParent
        FROM TB_LOGIN_VM
        WHERE UserName = %s AND Password = %s
        """
        cursor.execute(query, (username, password))

        # Obtém o primeiro resultado da consulta
        user_data = cursor.fetchone()

        # Fecha o cursor e a conexão
        cursor.close()
        db.close()

        # Se os dados de usuário não forem encontrados
        if not user_data:
            return jsonify({'message': 'Usuário ou senha inválidos'}), 401

        # Retorna os dados do usuário
        return jsonify(user_data)

    except Exception as e:
        # Em caso de erro, retorna uma mensagem de erro
        return jsonify({'error': str(e)}), 500

#########################################VERSION###########################################

@app.route('/VRProjectVersion/<int:version_id>', methods=['GET'])
def get_vr_project_version(version_id):
    try:
        # Cria uma nova conexão com o banco de dados
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(dictionary=True)

        # Consulta para buscar a versão com base no VersionID
        query = """
        SELECT versionID as VersionID, versionName as VersionName, BuildName
        FROM TB_VR_VERSION
        WHERE versionID = %s
        """
        cursor.execute(query, (version_id,))

        # Obtém o primeiro resultado da consulta
        version_data = cursor.fetchone()

        # Fecha o cursor e a conexão
        cursor.close()
        db.close()

        # Se a versão não for encontrada
        if not version_data:
            return jsonify({'message': 'Versão não encontrada para o ID fornecido'}), 404

        # Retorna os dados da versão
        return jsonify(version_data)

    except Exception as e:
        # Em caso de erro, retorna uma mensagem de erro
        return jsonify({'error': str(e)}), 500



#############################################SERIALIZE DATA################################################

@app.route('/SerializeData/<int:object_id>', methods=['DELETE'])
def delete_serialize_data(object_id):
    try:
        # Cria uma nova conexão com o banco de dados
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()

        # Consulta para verificar se o objeto existe
        cursor.execute("SELECT COUNT(*) FROM TB_SERIALIZE_DATA WHERE ID = %s", (object_id,))
        if cursor.fetchone()[0] == 0:
            cursor.close()
            db.close()
            return jsonify({'message': 'Objeto não encontrado'}), 404

        # Consulta para excluir o objeto com base no ID
        delete_query = "DELETE FROM TB_SERIALIZE_DATA WHERE ID = %s"
        cursor.execute(delete_query, (object_id,))

        # Faz o commit da transação
        db.commit()

        # Fecha o cursor e a conexão
        cursor.close()
        db.close()

        return jsonify({'message': 'Objeto excluído com sucesso'}), 200

    except Exception as e:
        # Em caso de erro, retorna uma mensagem de erro
        return jsonify({'error': str(e)}), 500



@app.route('/SerializeData', methods=['GET'])
def get_serialize_data():
    try:
        room_name = request.args.get('data')

        if not room_name:
            return jsonify({'error': 'Nome da sala (data) é necessário'}), 400

        db = mysql.connector.connect(**db_config)
        cursor = db.cursor(dictionary=True)

        # Consulta principal para buscar os dados com base no nome da sala
        query = """
        SELECT ID, Type, User, PositionX, PositionY, PositionZ, RotationX, RotationY, RotationZ, Data, ID_MAIN, ID_UNITY, UserID
        FROM TB_SERIALIZE_DATA
        WHERE Data LIKE %s
        """
        cursor.execute(query, (f'%{room_name}%',))

        serialize_data = []
        for row in cursor.fetchall():
            # Adiciona os dados do registro pai
            parent_data = OrderedDict({
                "ID": row["ID"],
                "Type": row["Type"],
                "User": row["User"],
                "Position": {
                    "X": row["PositionX"],
                    "Y": row["PositionY"],
                    "Z": row["PositionZ"]
                },
                "Rotation": {
                    "X": row["RotationX"],
                    "Y": row["RotationY"],
                    "Z": row["RotationZ"]
                },
                "Data": row["Data"],
                "Childs": [],
                "IDMAIN": row["ID_MAIN"],
                "IDUNITY": row["ID_UNITY"],
                "UserID": row["UserID"]
            })

            # Consulta para buscar registros filhos
            child_query = """
            SELECT ID, Type, User, PositionX, PositionY, PositionZ, RotationX, RotationY, RotationZ, Data, ID_MAIN, ID_UNITY, UserID
            FROM TB_SERIALIZE_DATA
            WHERE ID_MAIN = %s
            """
            cursor.execute(child_query, (row["ID"],))

            # Adiciona os dados dos registros filhos
            for child_row in cursor.fetchall():
                parent_data["Childs"].append(OrderedDict({
                    "ID": child_row["ID"],
                    "Type": child_row["Type"],
                    "User": child_row["User"],
                    "Position": {
                        "X": child_row["PositionX"],
                        "Y": child_row["PositionY"],
                        "Z": child_row["PositionZ"]
                    },
                    "Rotation": {
                        "X": child_row["PositionX"],
                        "Y": child_row["PositionY"],
                        "Z": child_row["PositionZ"]
                    },
                    "Data": child_row["Data"],
                    "Childs": [],
                    "IDMAIN": child_row["ID_MAIN"],
                    "IDUNITY": child_row["ID_UNITY"],
                    "UserID": child_row["UserID"]
            }))

            serialize_data.append(parent_data)

        cursor.close()
        db.close()

        return jsonify(serialize_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def insert_childs(cursor, parent_id, childs):
    for child in childs:
        cursor.execute("""
            INSERT INTO TB_SERIALIZE_DATA (Type, User, PositionX, PositionY, PositionZ, RotationX, RotationY, RotationZ, Data, ID_MAIN, ID_UNITY, UserID) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (child['Type'], child['User'], child['Position']['X'], child['Position']['Y'], child['Position']['Z'],
                  child['Rotation']['X'], child['Rotation']['Y'], child['Rotation']['Z'], child['Data'], parent_id,
                  child['IDUNITY'], child.get('UserID')))
        child['ID'] = cursor.lastrowid  # Atualizar ID do filho
        insert_childs(cursor, cursor.lastrowid, child.get('Childs', []))  # Recursivamente inserir filhos dos filhos

@app.route('/SerializeData', methods=['POST'])
def serialize_data():
    try:
        data = request.json
        db = db_pool.get_connection()
        cursor = db.cursor()

        # Inserir o registro pai
        cursor.execute("""
            INSERT INTO TB_SERIALIZE_DATA (Type, User, PositionX, PositionY, PositionZ, RotationX, RotationY, RotationZ, Data, ID_MAIN, ID_UNITY, UserID) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (data['Type'], data['User'], data['Position']['X'], data['Position']['Y'], data['Position']['Z'],
                  data['Rotation']['X'], data['Rotation']['Y'], data['Rotation']['Z'], data['Data'], data['IDMAIN'],
                  data['IDUNITY'], data.get('UserID')))
        parent_id = cursor.lastrowid
        data['ID'] = parent_id # Atualizar ID do pai
        #data['Childs']['IDMAIN'] = parent_id # Atualizando ID do filhote

        # Inserir os registros filhos
        if 'Childs' in data:
            insert_childs(cursor, parent_id, data['Childs'])
            # Atualizar IDMAIN para os filhos no objeto de retorno
            for child in data['Childs']:
                child['IDMAIN'] = parent_id

        db.commit()
        cursor.close()
        db.close()

        return jsonify(data)
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


################################################UPLOADSFILES###############################################
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        upload_folder = './uploads'
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        if 'file' not in request.files:
            return 'Nenhum arquivo enviado', 400
        file = request.files['file']
        if file.filename == '':
            return 'Nenhum arquivo selecionado', 400

        # Salvar o arquivo na pasta 'uploads'
        file.save(os.path.join(upload_folder, file.filename))
        return 'Arquivo recebido com sucesso', 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)