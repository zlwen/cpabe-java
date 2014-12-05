
%token  ATTR 
%token  NUM

%left OR
%left AND
%token OF

%%

result: policy { res = $1 }

policy:   ATTR                       { $$ = leaf_policy($1);        }
        | policy OR  policy          { $$ = kof2_policy(1, $1, $3); }
        | policy AND policy          { $$ = kof2_policy(2, $1, $3); }
        | NUM OF '(' arg_list ')'    { $$ = kof_policy($1, $4);     }
        | '(' policy ')'             { $$ = $2;                     }

arg_list: policy                     { $$ = new ArrayList<Policy>();
                                       $$.add($1); }
        | arg_list ',' policy        { $$ = $1;
                                       $$.add($1); }
;

%%
private Policy res;
String input;
StringTokenizer st;

private int yylex(){
	String s;
	int tok;
	if(!st.hasMoreTokens()){
		return 0;
	}
	s = st.nextToken();
	if(s.equals("&") || s.toLowerCase().equals("and")){
		tok = AND;
		yylval = new ParserVal(s);
	}
	else if(s.equals("|") || s.toLowerCase().equals("or")){
		tok = OR;
		yylval = new ParserVal(s);
	}
	else if(s.toLowerCase().equals("of")){
		tok = OF;
		yylval = new ParserVal(s);
	}
	else {
		boolean isNum = true;
		for( char c : s.toCharArray()){
			if(!Character.isDigit(c)){
				isNum = false;
				break;
			}
		}
		if(isNum){
			tok = NUM;
			yylval = new ParserVal(Integer.parserInt(s));
		}
		else{
			tok = ATTR;
			yylval = new ParserVal(s);
		}
	}

	return tok;
}

public void yyerror(String error){
	System.err.println("Error:" + error);
}


Policy leaf_policy(String attr){
	Policy p = new Policy();
	p.attr = attr;
	p.k = 1;
	return p;
}

Policy kof2_policy(int k, Policy l, Policy r){
	Policy p = new Policy();
	p.k = k;
	p.children = new Policy[2];
	p.children[0] = l;
	p.children[1] = r;
	return p;
}

Policy kof_policy(int k, List<Policy> list){
	Policy p = new Policy();
	p.k = k;
	p.children = new Policy[list.size()];
	list.toArray(p.children);
	return p;
}
