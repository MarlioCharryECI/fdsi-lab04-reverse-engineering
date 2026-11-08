//Renombra funciones/datos/variables del crackme_level2_stripped segun el analisis y exporta el decompilado anotado
//@category FDSI
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.util.*;
import java.io.*; import java.util.*;
public class AnnotateStripped extends GhidraScript {
  void ren(long a, String n) throws Exception { Function f=getFunctionAt(toAddr(a)); if(f!=null) f.setName(n, SourceType.USER_DEFINED); else createLabel(toAddr(a), n, true, SourceType.USER_DEFINED); }
  public void run() throws Exception {
    String out=getScriptArgs()[0];
    ren(0x401267,"main_recovered");
    ren(0x401156,"check_license");
    ren(0x4011f3,"print_secret_flag");
    ren(0x40208b,"XOR_KEY_4B");
    ren(0x402090,"EXPECTED_17B");
    createData(toAddr(0x40208b), new ArrayDataType(ByteDataType.dataType,4,1));
    createData(toAddr(0x402090), new ArrayDataType(ByteDataType.dataType,17,1));
    setPlateComment(toAddr(0x401156),"check_license: len==17 y para cada i: input[i]^XOR_KEY_4B[i%4] == EXPECTED_17B[i]\nAcumula diferencias con OR; retorna 1 solo si acumulador==0 (comparacion sin salida temprana)");
    setPlateComment(toAddr(0x4011f3),"print_secret_flag: 21 bytes XOR 0x37 -> putchar");
    setPlateComment(toAddr(0x401267),"main recuperado: entry -> __libc_start_main(FUN_00401267). Referencias a 'Invalid license.' y 'License accepted.'");
    // renombrar variables locales/params via HighFunction
    DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
    Map<String,String> m=new HashMap<>(); m.put("param_1","user_key"); m.put("sVar2","key_len"); m.put("bVar1","diff_acc"); m.put("local_18","i"); m.put("bVar3","is_valid");
    Map<String,String> mm=new HashMap<>(); mm.put("param_1","argc"); mm.put("param_2","argv"); mm.put("iVar1","ok"); mm.put("uVar2","exit_code");
    Map<String,String> mf=new HashMap<>(); mf.put("local_28","enc_flag"); mf.put("local_11","flag_xor"); mf.put("local_10","i");
    renameVars(di,0x401156,m); renameVars(di,0x401267,mm); renameVars(di,0x4011f3,mf);
    PrintWriter pw=new PrintWriter(new FileWriter(out));
    pw.println("// crackme_level2_stripped - decompilado DESPUES de renombrar (Ghidra "+getGhidraVersion()+")");
    for (long a: new long[]{0x401070,0x401267,0x401156,0x4011f3}) { Function f=getFunctionAt(toAddr(a)); DecompileResults r=di.decompileFunction(f,60,monitor); pw.println("\n// ===== "+f.getName()+" @ "+f.getEntryPoint()+" ====="); pw.println(r.getDecompiledFunction().getC()); }
    pw.close();
  }
  void renameVars(DecompInterface di,long a,Map<String,String> m) throws Exception {
    Function f=getFunctionAt(toAddr(a));
    for (int pass=0; pass<2; pass++) {
      DecompileResults r=di.decompileFunction(f,60,monitor); HighFunction hf=r.getHighFunction();
      Iterator<HighSymbol> it=hf.getLocalSymbolMap().getSymbols();
      List<HighSymbol> l=new ArrayList<>(); while(it.hasNext()) l.add(it.next());
      for (HighSymbol s: l) { String nn=m.get(s.getName()); if(nn!=null) { try { HighFunctionDBUtil.updateDBVariable(s, nn, null, SourceType.USER_DEFINED);} catch(Exception e){ println("skip "+s.getName()+": "+e.getMessage()); } } }
    }
  }
}
