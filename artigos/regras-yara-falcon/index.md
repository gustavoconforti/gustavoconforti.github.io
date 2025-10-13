# Regras YARA no CrowdStrike Falcon (MalQuery)

Para melhor compreender a função e o funcionamento das regras YARA, vale primeiro passar por alguns conceitos fundamentais em análise de
_malwares_.

## Detecção baseada em _hashes_


Uma das formas de catalogar arquivos em um computador é através de seu _hash_ , pois ele é único e exclusivo; cada arquivo possui um _hash_ singular,
dois arquivos diferentes não podem possuir o mesmo. Isso geralmente é feito utilizando mais de um algorítmo criptográfico, como MD5, SHA-1 e SHA-
256, para evitar eventuais colisões.


> [!NOTE]
> **Complemento: Algorítmos criptográficos**
>
> Um algorítmo criptográfico (MD5, SHA-1, SHA-256, etc.) é a tradução para software de uma função criptográfica (a _hashing function_) baseada nos
princípios da aritmética modular. 
>
> O _hash_ (ou _message disgest_), por sua vez, é o resultado final de uma função criptográfica que, no nosso caso, ingere um determinado dado (uma
string , um arquivo, etc.).
>
> ```
> 📄 malware.exe → MD5 → 0b36236f11f81d5247f26d6b39b8380d
>"abc" → SHA-256 → ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
>"abc1" → SHA-256 → dbfcfd0d87220f629339bd3adcf452d083fde3246625fb3a93e314f833e20d
>```

Em suma:


- Sempre (idealmente) que a origem for a mesma, o _hash_  será o mesmo
- Chamamos de "colisão" quando duas origens diferentes geram um mesmo _hash_;  algorítmos que possibilitam esse erro são considerados
falhos
- O _hash_ tem sempre o mesmo comprimento, não importa o tamanho da informação que entra
- Qualquer alteração mínima na origem gera um _hash_  completamente diferente
- É impossível deduzir a informação original através da engenharia reversa de um  _hash_, somente através de força bruta (testar todas as origens
possíveis até encontrar a correta)


Mais detalhes sobre o assunto em [What is Modular Arithmetic](https://www.youtube.com/watch?v=Eg6CTCu8iio) e [How Does SHA-256 Work?](https://www.youtube.com/watch?v=f9EbD6iY9zI&list=FLQrhpNpCy_SZoEvKCJgcRZQ&index=16).

É por isso então que usamos _file hashes_ como _IoCs_ e é também como boa parte das ferramentas de antivírus ainda criam assinaturas.

Entretanto, atacantes se utilizam desses mesmos princípios das funções criptográficas para evadir sistemas de defesa que usam delas como principal
mecanismo; se mínimas alterações no dado ingerido geram grandes discrepâncias no _message digest_ final, então a simples adição ou remoção de
pedaços de código ou texto no arquivo final do _malware_ é o suficiente para burlar esses simples sistema de defesa.

## Detecção baseada em padrões textuais e binários

As alterações supracitadas, porém, são meramente cosméticas; elas não alteram a real funcionalidade do executável. Um atacante pode escrever uma
função que nunca será utilizada, ou embaralhar a ordem de execução de partes do código. O que ele não pode fazer é alterar o endereço do servidor
_C&C_ a ser contatado, ou o comando que será executado via PowerShell, pois nesses caso o programa não funcionaria.

É aí que está o grande pulo do gato: essas (URLs, IPs, caminhos e comandos) são variáveis estáticas ou valores _hardcoded_ , que eventualmente precisam
ser alocados em memória. Pela simples natureza do processo, esses valores sobrevivem toda a esteira de compilação do código, sendo armazenados de
forma inalterada em um segmento específico do binário final. 

> [!NOTE]
> **Complemento: Compilação e arquivos binários**
>
>Um arquivo binário é o resultado final do processo de compilação de um código. Esse processo, de forma simplificada, ocorre da seguinte forma:
>
>1. Um arquivo fonte escrito em uma linguagem de alto nível (C++, Ruby, Java) serve como entrada na esteira de compilação.
>
>```
>int print() {
>std::cout << "Hello, World"; ← Valor hardcoded
>return 0;
>}
>```
>2. Nas fases de _preprocessing_ e _compilation_ o código escrito em alto nível é limpo, reorganizado e transformado >em um conjunto de instruções
>Assembly que a arquitetura do processador de destino é capaz de interpretar.
>
>```
>global _start
>section .text
>_start:
>mov rax, 1
>mov rdi, 1
>mov rsi, message
>mov rdx, 13
>syscall
>mov eax, 60
>xor rdi, rdi
>syscall
>message:
>db "Hello, World", 10 ← Valor hardcoded
>```
>3. Por fim, nas fases de _assembly_ e _linking_  o produto do passo anterior é transformado em linguagem binária pura e o arquivo final recebe _entry
>point_ , permitindo a sua execução. Esse é o executável que analisamos.
>
>```
>00000000 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 |.ELF............|
>00000010 01 00 3e 00 01 00 00 00 00 00 00 00 00 00 00 00 |..>.............|
>00000020 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 |........@.......|
>00000030 00 00 00 00 40 00 00 00 00 00 40 00 06 00 02 00 |....@.....@.....|
>[...]
>000001c0 b8 01 00 00 00 bf 01 00 00 00 48 be 00 00 00 00 |..........H.....|
>000001d0 00 00 00 00 ba 0d 00 00 00 0f 05 b8 3c 00 00 00 |............<...|
>000001e0 48 31 ff 0f 05 48 65 6c 6c 6f 2c 20 57 6f 72 6c |H1...Hello, Worl| ← Valor hardcoded
>000001f0 64 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |d...............|
>[...]
>```


Mais sobre os assuntos em [What are EXE files?](https://www.youtube.com/watch?v=hhgxsrAFyz8&t=531s), [C and C++ compilation process](https://www.youtube.com/watch?v=ksJ9bdSX5Yo&t=2348s) e [Assembly: Hello World!](https://www.youtube.com/watch?v=HgEGAaYdABA&t=12s).

Isso significa dizer que, por mais que o programador altere seu código a fim de burlar ferramentas defensivas baseadas em _hashes_ , a necessidade de
manter a funcionalidade do mesmo inevitavelmente gerará artefatos únicos de identificação, esses que poderemos eventualmente utilizar na
catalogação de um determinado pedaço de _malware_. Essa coleta de informações pode ser feita manualmente através da análise estática do arquivo em


questão (enquanto ele descansa em disco) ou da análise dinâmica do mesmo (quando ele é executado e os códigos de operação são alocados em
memória).

Toda essa história é muito feliz e bonita... mas só até a página 2. Nela descobrimos que essas atividades demandam tempo e conhecimento em
demasia, e no fim das contas acabam ficando quase que exclusivamente nas mãos de profissionais forenses de grandes empresas de _threat intelligence_.

Por esse motivo que, em novembro 2013, [Victor Alvarez](https://github.com/plusvic), então funcionário da [VirusTotal](https://www.virustotal.com/gui/home/url), criou...

## YARA

YARA (_Yet Another Ridiculous Acronym_ segundo Wikipedia) provê à profissionais indepentes e à grande comunidade, de forma aberta e totalmente
grátis, uma ferramenta de catalogação e detecção de _malware_ baseada em regras, que analisam os padrões textuais ou binários (esses que acabamos
de abordar) de forma altamente escalável.

Uma regra YARA contém duas seções principais:


- _strings_ : Padrões textuais ou binários a serem buscados nos arquivos
- _condition_ : Organização lógica de busca desses padrões

No exemplo abaixo são declaradas as _strings_ $a, $b e $c e a  _condition_  diz que a regra disparará ao encontrar qualquer um desses padrões em um
determinado arquivo.

```
rule silent_banker : banker
{
meta:
description = "This is just an example"
threat_level = 3
in_the_wild = true
strings:
$a = {6A 40 68 00 30 00 00 6A 14 8D 91}
$b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
$c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
condition:
$a or $b or $c
}
```
Esse é realmente o fundamental a se saber, porém mais detalhes de funcionamento das regras YARA podem ser encontrados em [Welcome to YARA's documentation!](https://yara.readthedocs.io/en/stable/).

Existem diversas formas de utilizar essa ferramenta, como através do [projeto público do GitHub](https://github.com/VirusTotal/yara/releases) ou pela implementação de uma [aplicação terceira](https://github.com/VirusTotal/yara#whos-using-yara).
Podemos também usá-la em diferentes momentos do ciclo de vida de uma análise, como na resposta ao incidente, no processo de _threat hunting_ ou na
eliminação de falsos positivos. Estarei me atendo a aplicação dessa ferramenta dentro das possibilidades do escopo da Nelogica, que é composto
atualmente apenas pelo nosso EDR, o Crowdstrike Falcon.

## Regras YARA no Falcon

Novamente, as regas YARA podem fazer parte de diversas fases de um processo de análise de _malware_. Tendo estabelecidos os conceitos abordados
anteriormente, o consumo das informações [deste vídeo](https://github.com/VirusTotal/yara#whos-using-yara) é suficiente para entender a utilização das regras YARA no Falcon, através da base [MalQuery](https://falcon.us-2.crowdstrike.com/login?next=%2Fdocumentation%2F18%2Ffalcon-malquery) (requer conta CrowdStrike).
Em suma:


- MalQuery é uma coleção gigantesca de arquivos maliciosos (na casa dos petabytes , ampliada a cada 8 horas) que vem sendo curada desde 2012 pela
CrowdStrike.
- O incident responder consulta esse repositórios baseado em um incidente em execução/já ocorrido no ambiente local. Ele utiliza de padrões textuais,
binários e/ou hexadecimais presentes nessa amostra encontrada para buscar mais informações sobre o malware em questão (se está ligado a algum
threat actor , se faz parte de um família específica de malwares , quando foi identificado pela primeira vez, etc.).
- Com relação à regras YARA, a MalQuery funciona como uma base validadora de falsos positivos. Tendo uma regra já criada, baseada em um processo
preestabelecido de análise de malware (retornaremos nesse ponto na conclusão), o investigador roda tal consulta YARA contra o MalQuery, a fim de
projetar se ela será efetiva em um cenário real. Diferente de outras ferramentas de mercado que atendem o mesmo propósito, a MalQuery conta com
um tempo de resposta na casa dos minutos, facilitando a realização de ajustes mediante consultas subsequentes (limitando apenas o número de
consultas mensais, limite esse acordado na aquisição da licença de uso).

Contrariando a minha expectativa no início desse estudo, o Falcon não é capaz de rodar consultas YARA contra os _filesystems_ do ambiente protegido
pelo agente. Não encontrei documentação oficial sobre essa "limitação", somente a seguinte [thread](https://www.reddit.com/r/crowdstrike/comments/k9t7rf/yara_rule_monitoring_via_cs/) do _subreddit_ [r/crowdstrike](https://www.reddit.com/r/crowdstrike/comments/lc9yb5/new_to_crowdstrike_read_this_thread_first/).



# Conclusão


A funcionalidade fornecida pelo MalQuery é avançada, apenas uma das ferramentas que compõe um processo complexo de resposta à incidentes.
Precisamos do arroz com feijão bem feito em nossas organizações, um plano de resposta à incidentes maduro para, somente depois disso, usarmos da análise de malwares com regras YARA e gerar ações de bloqueio em larga escala.
