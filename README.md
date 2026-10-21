## NetBoX - Testes e Verificação

# Limpar compilações anteriores e gerar o executável 'user'
make clean
make all

# Executar a aplicação com os parâmetros definidos no Makefile
make run

# Publish
publish testfile.txt 1080p

# Sessão

login 157498 passpasb
exit
logout
unregister

# Listar
list

# Remover
remove testfile.txt

# Versões
versions testfile.txt

# Download de Ficheiro
get testfile.txt
get testfile.txt 157498

# Para a fase III:
    # Num primeiro terminal entrar com o port 58000 -> fazer login e publish
    # Num segundo terminal entrar com o path
    /Users/manuelsoares/Desktop/tekas/3ano/semestre1/RC/project/CN-Project/user -m 58001

    
