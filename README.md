## NetBoX - Testes e Verificação (Fase III)

# Limpar compilações anteriores e gerar o executável 'user'
make clean
make all

# Executar a aplicação com os parâmetros definidos no Makefile
make run

# Sessão
login 157498 passpasb
logout
unregister
exit

# Recursos (UDP)
publish testfile.txt 1080p
list
remove testfile.txt

# Versões (TCP com DS)
versions testfile.txt

# Download de Ficheiro (TCP Peer-to-Peer)
get testfile.txt
get testfile.txt 157498

# Para testes multi-peer da fase III:
# No primeiro terminal (User 1):
./user -m 58000
# Fazer login e publish de um ficheiro

# No segundo terminal (User 2):
./user -m 58001
# Executar 'versions <ficheiro>', 'where <ficheiro>' ou 'get <ficheiro>' para transferir
