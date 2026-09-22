## NetBoX - Testes e Verificação

# Limpar compilações anteriores e gerar o executável 'user'
make clean
make all

# Executar a aplicação com os parâmetros definidos no Makefile (Porto 58000 e DS tejo.tecnico.ulisboa.pt)
make run

# Publish
publish testfile.txt 1080p

publish ficheiro_falso.txt 720p

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