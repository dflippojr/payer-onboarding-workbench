package io.github.dflippojr.payerworkbench.app;
import io.github.dflippojr.payerworkbench.core.*;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.time.*;
import java.util.*;
import java.lang.management.ManagementFactory;
public class VerdictBench {
static volatile String sink;
static String direct(OnboardingRun r) { return RunVerdict.of(r).status(); }
static void measure(OnboardingRun r,boolean full,int n) {
 var bean=(com.sun.management.ThreadMXBean)ManagementFactory.getThreadMXBean();
 long tid=Thread.currentThread().threadId(), alloc=bean.getThreadAllocatedBytes(tid), start=System.nanoTime();
 for(int i=0;i<n;i++) sink=full?RunReport.of(r,null,null,Instant.EPOCH,"").verdict().status():direct(r);
 long time=System.nanoTime()-start, bytes=bean.getThreadAllocatedBytes(tid)-alloc;
 System.out.printf(Locale.ROOT,"%s n=%d us/op=%.3f bytes/op=%.1f%n",full?"full-report":"shared-verdict",n,time/1000.0/n,bytes*1.0/n);
}
public static void main(String[] args) {
 System.out.println(System.getProperty("java.version"));
 for(int size: new int[]{4096,65536}) {
 String body="{\"resourceType\":\"Bundle\",\"syntheticPadding\":\""+"a".repeat(size)+"\"}";
 List<StepResult> steps=new ArrayList<>();
 for(String id:List.of("resolve-connection","discovery","authenticate","hook-request","parse-response","diagnostics")) {
 Map<String,Object> detail = Set.of("discovery","authenticate","hook-request").contains(id)?Map.of("status","passed","exchanges",List.of(Map.of("method","POST","url","https://payer.example/cds-services","status",200,"latencyMs",12,"requestBody",body,"responseBody",body))):Map.of("status","passed");
 steps.add(new StepResult(id,Instant.EPOCH,Duration.ofMillis(12),true,"Synthetic step",detail));
 }
 List<Finding> findings=new ArrayList<>();
 for(int i=0;i<14;i++)findings.add(new Finding("check."+i,Severity.PASS,"Synthetic check","Synthetic explanation","Synthetic evidence",null));
 OnboardingRun r=new OnboardingRun("synthetic-run","northwind-synthetic",Environment.SANDBOX,steps,findings);
 for(int i=0;i<300;i++){sink=RunReport.of(r,null,null,Instant.EPOCH,"").verdict().status();sink=direct(r);}
 System.out.println("size="+size+" six bodies three exchanges six steps fourteen findings");
 for(int rep=0;rep<5;rep++){measure(r,true,500);measure(r,false,100000);}
 }
}
}
