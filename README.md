# Port Scanner 2

Projeto desenvolvido para a disciplina de Tecnologias Hacker, 7° semestre de Engenharia de Computação do Insper

## Como utilizar

Clone o repositório:
```terminal
git clone https://github.com/rafaelgpaves/port-scanner-2.git
```

Entre na pasta do repositório:
```terminal
cd port-scanner-2
```

É recomendado criar um env (opcional):
```terminal
python -m venv env
env/Scripts/activate
```

Instale as bibliotecas:
```terminal
pip install -r ./requirements.txt
```

Rode o aplicativo:
```terminal
python main.py
```

Haverá um menu as ferramentas disponíveis atualmente:
1. Port Scanner
2. whois
3. wappalyzer
4. wafw00f
5. Subdomain Scanner
0. Sair

## Ferramentas implementadas

Para esse projeto, foram implementadas as seguintes ferramentas:

### Port Scanner

Haverá um menu com várias possíveis ações:
1. Definir o IP do host
2. Definir o IP da rede
3. Escanear portas (TCP)
4. Escanear portas (UDP)
5. Detectar OS
6. Escanear hosts conectados a sua rede
0. Sair

Antes de fazer qualquer coisa, defina o IP do host (opção 1), podendo ser IPv4 ou IPv6 ou IP da rede e sua máscara de subnet (opção 2) que quer escanear.

Após especificar um IP para o host, selecione a opção 3 para escanear as portas TCP abertas ou a opção 4 para escanear as portas UDP abertas em um host específico

Acabando um desses dois, é possível selecionar a opção 5, que tenta detectar o sistema operacional do host utilizando *banner grabbing*. Isso depende de portas específicas estarem abertas, então um bom teste pra ver se está funcionando é testar o IP *45.33.32.156*.

Após especificar um IP da rede e máscara da subnet, selecione a opção 6 para tentar descobrir todos os IPs conectados nessa rede. Os dois modos possíveis são:
1. Busca extensiva --> basicamente tenta se conectar com portas conhecidas em todos os IPs possíveis e vê quais estão disponíveis (pode demorar bastante)
2. Envio pacote ARP --> envia um pacote "falso" pra rede e vê quem responde (CUIDADO COM ISSO, REQUER PERMISSÃO SUDO!)

### whois

Ferramenta utilizada para obter informações sobre o dono do site. 

Para usá-la, pode-se definir o IP que deseja escanear (a partir do menu do Port Scanner) ou digitar uma url.

As duas opções implementadas são:
- Análise resumida (inclui apenas algumas informações, como nome do domínio, datas de criação, expiração e atualização, name servers, emails e país)
- Análise completa (inclui todas as informações obtidas).

### wappalyzer

Ferramenta utilizada para obter inforações sobre as tecnologias utilizadas pelo site. As três opções implementadas são:
- Rápido
- Balanceado
- Completo

### wafw00f

Ferramenta utilizada para identificar se o site possui algum tipo de WAF (Web Application Firewall).

Ao utilizar esta ferramenta, coloque *http/https* no começo da url. Por exemplo:
- https://www.stackoverflow.com **vai** funcionar.
- stackoverflow.com **não vai** funcionar.

### Subdomain Scanner

Ferramenta utilizada para enumerar subdomínios que um site pode ter.

Ao utilizar esta ferramenta, não coloque *http/https* nem *www.* no começo da url. Por exemplo:
- stackoverflow.com **vai** funcionar.
- https://www.stackoverflow.com **não vai** funcionar.
