# Analisando um Binário Fictício

A análise de binários é uma prática comum em segurança da informação, engenharia reversa e depuração de software.  
Por meio dela, é possível compreender a estrutura interna de um arquivo executável, biblioteca ou qualquer outro tipo de dado compilado.

Neste exemplo, observaremos um pequeno binário fictício chamado `sample.bin` e faremos uma breve análise visual utilizando uma representação hexadecimal e ASCII.

---

## Representação Hexadecimal e ASCII

Abaixo está a saída simulada de uma ferramenta como `xxd`, que exibe os dados do binário em dois formatos: hexadecimal e ASCII.

```bash
00000000  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  |MZ............|
00000010  B8 00 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01  |............!..|
00000020  4C CD 21 54 68 69 73 20 69 73 20 61 20 74 65 73  |L.!This is a tes|
00000030  74 20 66 69 6C 65 2E 00 00 00 00 00 00 00 00 00  |t file..........|
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```
O formato segue o padrão:

- **Coluna 1:** Posição (offset) do primeiro byte da linha no arquivo, em hexadecimal.  
- **Coluna 2:** Sequência de bytes em formato hexadecimal.  
- **Coluna 3:** Representação ASCII dos bytes (quando legíveis).

Essa forma de visualização é extremamente útil para identificar padrões, cabeçalhos e possíveis assinaturas em arquivos.

---

## O Cabeçalho “MZ”

Os dois primeiros bytes `4D 5A` correspondem à sequência ASCII **“MZ”**, que é o cabeçalho tradicional de arquivos executáveis do Windows (formato **PE – Portable Executable**).  
Essas iniciais vêm de **Mark Zbikowski**, um dos engenheiros originais da Microsoft que trabalhou no formato executável do MS-DOS.

Embora este seja apenas um arquivo fictício, a presença do cabeçalho “MZ” indica que ele foi simulado para parecer um executável.

---

## Identificação de Strings

Mais adiante, observamos o trecho ASCII:

