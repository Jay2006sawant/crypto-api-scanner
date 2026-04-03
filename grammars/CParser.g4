grammar CParser;

compilationUnit
    : (statement | OTHER)* EOF
    ;

statement
    : functionCall SEMI
    ;

functionCall
    : IDENTIFIER LPAREN argumentList? RPAREN
    ;

argumentList
    : argument (COMMA argument)*
    ;

argument
    : functionCall
    | ATOM
    ;

IDENTIFIER : [a-zA-Z_][a-zA-Z_0-9]* ;
LPAREN     : '(' ;
RPAREN     : ')' ;
COMMA      : ',' ;
SEMI       : ';' ;
ATOM       : ~[(),;\r\n]+ ;
OTHER      : . ;
WS         : [ \t\r\n]+ -> skip ;
