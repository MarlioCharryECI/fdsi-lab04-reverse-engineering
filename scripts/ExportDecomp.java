//Exporta decompilado + referencias de strings a un archivo
//@category FDSI
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.util.DefinedDataIterator;
import java.io.*;
public class ExportDecomp extends GhidraScript {
  public void run() throws Exception {
    String out = getScriptArgs()[0];
    PrintWriter pw = new PrintWriter(new FileWriter(out));
    DecompInterface di = new DecompInterface(); di.openProgram(currentProgram);
    pw.println("// Programa: "+currentProgram.getName()+" | Ghidra "+getGhidraVersion());
    pw.println("// ===== Strings definidas y sus referencias (XREFs) =====");
    for (Data d : DefinedDataIterator.definedStrings(currentProgram)) {
      String s = String.valueOf(d.getValue()); if (s.length()<4) continue;
      StringBuilder sb=new StringBuilder();
      for (Reference r : getReferencesTo(d.getAddress())) { Function f=getFunctionContaining(r.getFromAddress()); sb.append(r.getFromAddress()).append("(").append(f==null?"?":f.getName()).append(") "); }
      pw.println("// "+d.getAddress()+"  \""+s.replace("\n","\\n")+"\"  <- "+sb);
    }
    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
    while (it.hasNext()) {
      Function f = it.next();
      if (f.isExternal() || f.isThunk()) continue;
      String n=f.getName();
      if (n.startsWith("_") || n.equals("deregister_tm_clones")||n.equals("register_tm_clones")||n.equals("frame_dummy")||n.startsWith("FUN_00401000")) continue;
      DecompileResults r = di.decompileFunction(f, 60, monitor);
      pw.println("\n// ===== "+n+" @ "+f.getEntryPoint()+" =====");
      pw.println(r.decompileCompleted()? r.getDecompiledFunction().getC() : "// fallo: "+r.getErrorMessage());
    }
    pw.close();
  }
}
