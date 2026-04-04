package com.cryptoscanner.scanner;

import com.cryptoscanner.model.Finding;
import com.cryptoscanner.parser.CParserBaseListener;
import com.cryptoscanner.parser.CParserLexer;
import com.cryptoscanner.parser.CParserParser;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.DefaultErrorStrategy;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class CFileScanner {
    private final OpenSSLDetector detector = new OpenSSLDetector();
    private static final BaseErrorListener SILENT_ERROR_LISTENER = new BaseErrorListener() {
        @Override
        public void syntaxError(Recognizer<?, ?> recognizer, Object offendingSymbol, int line, int charPositionInLine,
                                String msg, RecognitionException e) {
            // Intentionally suppress syntax errors; grammar is intentionally narrow.
        }
    };

    public List<Finding> scan(Path sourceFile) throws IOException {
        CParserLexer lexer = new CParserLexer(CharStreams.fromPath(sourceFile));
        lexer.removeErrorListeners();
        lexer.addErrorListener(SILENT_ERROR_LISTENER);
        CommonTokenStream tokens = new CommonTokenStream(lexer);
        CParserParser parser = new CParserParser(tokens);
        parser.removeErrorListeners();
        parser.addErrorListener(SILENT_ERROR_LISTENER);
        parser.setErrorHandler(new DefaultErrorStrategy());

        List<Finding> findings = new ArrayList<>();
        ParseTreeWalker.DEFAULT.walk(new CParserBaseListener() {
            @Override
            public void enterFunctionCall(CParserParser.FunctionCallContext ctx) {
                String functionName = ctx.IDENTIFIER().getText();
                String rawArguments = "";
                if (ctx.argumentList() != null) {
                    rawArguments = tokens.getText(ctx.argumentList());
                }
                int lineNumber = ctx.getStart().getLine();
                Finding finding = detector.detect(sourceFile.toString(), lineNumber, functionName, rawArguments);
                if (finding != null) {
                    findings.add(finding);
                }
            }
        }, parser.compilationUnit());
        return findings;
    }
}
