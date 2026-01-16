import{ax as S,as as z,bR as Z,_ as p,C as j,A as J,D as Y,E as q,Z as H,Y as K,I as F,G as Q,a8 as X,ac as ee,ah as te,J as ae,a3 as re,aa as ne}from"./main-DSyDihWl.js";import{p as ie}from"./chunk-4BX2VUAB-BwoQ30uy.js";import{p as se}from"./treemap-KMMF4GRG-wxanDtTs.js";import{d as P}from"./arc-BDQcphPg.js";import{o as le}from"./ordinal-Cboi1Yqb.js";import"./min-BUlZXzip.js";import"./_baseUniq-6t3aA0wu.js";import"./init-Gi6I4Gst.js";function oe(e,a){return a<e?-1:a>e?1:a>=e?0:NaN}function ce(e){return e}function ue(){var e=ce,a=oe,f=null,x=S(0),s=S(z),o=S(0);function l(t){var n,c=(t=Z(t)).length,d,y,m=0,u=new Array(c),i=new Array(c),v=+x.apply(this,arguments),A=Math.min(z,Math.max(-z,s.apply(this,arguments)-v)),h,C=Math.min(Math.abs(A)/c,o.apply(this,arguments)),$=C*(A<0?-1:1),g;for(n=0;n<c;++n)(g=i[u[n]=n]=+e(t[n],n,t))>0&&(m+=g);for(a!=null?u.sort(function(w,D){return a(i[w],i[D])}):f!=null&&u.sort(function(w,D){return f(t[w],t[D])}),n=0,y=m?(A-c*$)/m:0;n<c;++n,v=h)d=u[n],g=i[d],h=v+(g>0?g*y:0)+$,i[d]={data:t[d],index:n,value:g,startAngle:v,endAngle:h,padAngle:C};return i}return l.value=function(t){return arguments.length?(e=typeof t=="function"?t:S(+t),l):e},l.sortValues=function(t){return arguments.length?(a=t,f=null,l):a},l.sort=function(t){return arguments.length?(f=t,a=null,l):f},l.startAngle=function(t){return arguments.length?(x=typeof t=="function"?t:S(+t),l):x},l.endAngle=function(t){return arguments.length?(s=typeof t=="function"?t:S(+t),l):s},l.padAngle=function(t){return arguments.length?(o=typeof t=="function"?t:S(+t),l):o},l}var pe=ne.pie,G={sections:new Map,showData:!1},T=G.sections,N=G.showData,de=structuredClone(pe),ge=p(()=>structuredClone(de),"getConfig"),fe=p(()=>{T=new Map,N=G.showData,re()},"clear"),he=p(({label:e,value:a})=>{if(a<0)throw new Error(`"${e}" has invalid value: ${a}. Negative values are not allowed in pie charts. All slice values must be >= 0.`);T.has(e)||(T.set(e,a),F.debug(`added new section: ${e}, with value: ${a}`))},"addSection"),me=p(()=>T,"getSections"),ve=p(e=>{N=e},"setShowData"),Se=p(()=>N,"getShowData"),L={getConfig:ge,clear:fe,setDiagramTitle:K,getDiagramTitle:H,setAccTitle:q,getAccTitle:Y,setAccDescription:J,getAccDescription:j,addSection:he,getSections:me,setShowData:ve,getShowData:Se},xe=p((e,a)=>{ie(e,a),a.setShowData(e.showData),e.sections.map(a.addSection)},"populateDb"),ye={parse:p(async e=>{const a=await se("pie",e);F.debug(a),xe(a,L)},"parse")},Ae=p(e=>`
  .pieCircle{
    stroke: ${e.pieStrokeColor};
    stroke-width : ${e.pieStrokeWidth};
    opacity : ${e.pieOpacity};
  }
  .pieOuterCircle{
    stroke: ${e.pieOuterStrokeColor};
    stroke-width: ${e.pieOuterStrokeWidth};
    fill: none;
  }
  .pieTitleText {
    text-anchor: middle;
    font-size: ${e.pieTitleTextSize};
    fill: ${e.pieTitleTextColor};
    font-family: ${e.fontFamily};
  }
  .slice {
    font-family: ${e.fontFamily};
    fill: ${e.pieSectionTextColor};
    font-size:${e.pieSectionTextSize};
    // fill: white;
  }
  .legend text {
    fill: ${e.pieLegendTextColor};
    font-family: ${e.fontFamily};
    font-size: ${e.pieLegendTextSize};
  }
`,"getStyles"),we=Ae,De=p(e=>{const a=[...e.values()].reduce((s,o)=>s+o,0),f=[...e.entries()].map(([s,o])=>({label:s,value:o})).filter(s=>s.value/a*100>=1).sort((s,o)=>o.value-s.value);return ue().value(s=>s.value)(f)},"createPieArcs"),Ce=p((e,a,f,x)=>{F.debug(`rendering pie chart
`+e);const s=x.db,o=Q(),l=X(s.getConfig(),o.pie),t=40,n=18,c=4,d=450,y=d,m=ee(a),u=m.append("g");u.attr("transform","translate("+y/2+","+d/2+")");const{themeVariables:i}=o;let[v]=te(i.pieOuterStrokeWidth);v??=2;const A=l.textPosition,h=Math.min(y,d)/2-t,C=P().innerRadius(0).outerRadius(h),$=P().innerRadius(h*A).outerRadius(h*A);u.append("circle").attr("cx",0).attr("cy",0).attr("r",h+v/2).attr("class","pieOuterCircle");const g=s.getSections(),w=De(g),D=[i.pie1,i.pie2,i.pie3,i.pie4,i.pie5,i.pie6,i.pie7,i.pie8,i.pie9,i.pie10,i.pie11,i.pie12];let E=0;g.forEach(r=>{E+=r});const R=w.filter(r=>(r.data.value/E*100).toFixed(0)!=="0"),b=le(D);u.selectAll("mySlices").data(R).enter().append("path").attr("d",C).attr("fill",r=>b(r.data.label)).attr("class","pieCircle"),u.selectAll("mySlices").data(R).enter().append("text").text(r=>(r.data.value/E*100).toFixed(0)+"%").attr("transform",r=>"translate("+$.centroid(r)+")").style("text-anchor","middle").attr("class","slice"),u.append("text").text(s.getDiagramTitle()).attr("x",0).attr("y",-400/2).attr("class","pieTitleText");const W=[...g.entries()].map(([r,M])=>({label:r,value:M})),k=u.selectAll(".legend").data(W).enter().append("g").attr("class","legend").attr("transform",(r,M)=>{const O=n+c,B=O*W.length/2,V=12*n,U=M*O-B;return"translate("+V+","+U+")"});k.append("rect").attr("width",n).attr("height",n).style("fill",r=>b(r.label)).style("stroke",r=>b(r.label)),k.append("text").attr("x",n+c).attr("y",n-c).text(r=>s.getShowData()?`${r.label} [${r.value}]`:r.label);const _=Math.max(...k.selectAll("text").nodes().map(r=>r?.getBoundingClientRect().width??0)),I=y+t+n+c+_;m.attr("viewBox",`0 0 ${I} ${d}`),ae(m,d,I,l.useMaxWidth)},"draw"),$e={draw:Ce},Ne={parser:ye,db:L,renderer:$e,styles:we};export{Ne as diagram};
