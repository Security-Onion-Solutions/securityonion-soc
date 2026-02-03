import{aI as S,aD as W,bW as j,_ as p,O as Q,N as Y,P as Z,Q as q,aa as H,a9 as J,W as z,U as K,ak as X,ao as ee,at as te,Y as ae,af as re,am as ne}from"./main-9FWdZh3Y.js";import{p as ie}from"./chunk-4BX2VUAB-BPtRwk8x.js";import{p as se}from"./treemap-KMMF4GRG-NnSzKgeq.js";import{d as R}from"./arc-DqEYIHq5.js";import{o as le}from"./ordinal-Cboi1Yqb.js";import"./min-BsXi12ba.js";import"./_baseUniq-XDCSLbCI.js";import"./init-Gi6I4Gst.js";function oe(e,a){return a<e?-1:a>e?1:a>=e?0:NaN}function ce(e){return e}function ue(){var e=ce,a=oe,f=null,x=S(0),s=S(W),o=S(0);function l(t){var n,c=(t=j(t)).length,d,y,h=0,u=new Array(c),i=new Array(c),v=+x.apply(this,arguments),w=Math.min(W,Math.max(-W,s.apply(this,arguments)-v)),m,C=Math.min(Math.abs(w)/c,o.apply(this,arguments)),$=C*(w<0?-1:1),g;for(n=0;n<c;++n)(g=i[u[n]=n]=+e(t[n],n,t))>0&&(h+=g);for(a!=null?u.sort(function(A,D){return a(i[A],i[D])}):f!=null&&u.sort(function(A,D){return f(t[A],t[D])}),n=0,y=h?(w-c*$)/h:0;n<c;++n,v=m)d=u[n],g=i[d],m=v+(g>0?g*y:0)+$,i[d]={data:t[d],index:n,value:g,startAngle:v,endAngle:m,padAngle:C};return i}return l.value=function(t){return arguments.length?(e=typeof t=="function"?t:S(+t),l):e},l.sortValues=function(t){return arguments.length?(a=t,f=null,l):a},l.sort=function(t){return arguments.length?(f=t,a=null,l):f},l.startAngle=function(t){return arguments.length?(x=typeof t=="function"?t:S(+t),l):x},l.endAngle=function(t){return arguments.length?(s=typeof t=="function"?t:S(+t),l):s},l.padAngle=function(t){return arguments.length?(o=typeof t=="function"?t:S(+t),l):o},l}var pe=ne.pie,F={sections:new Map,showData:!1},T=F.sections,N=F.showData,de=structuredClone(pe),ge=p(()=>structuredClone(de),"getConfig"),fe=p(()=>{T=new Map,N=F.showData,re()},"clear"),me=p(({label:e,value:a})=>{if(a<0)throw new Error(`"${e}" has invalid value: ${a}. Negative values are not allowed in pie charts. All slice values must be >= 0.`);T.has(e)||(T.set(e,a),z.debug(`added new section: ${e}, with value: ${a}`))},"addSection"),he=p(()=>T,"getSections"),ve=p(e=>{N=e},"setShowData"),Se=p(()=>N,"getShowData"),L={getConfig:ge,clear:fe,setDiagramTitle:J,getDiagramTitle:H,setAccTitle:q,getAccTitle:Z,setAccDescription:Y,getAccDescription:Q,addSection:me,getSections:he,setShowData:ve,getShowData:Se},xe=p((e,a)=>{ie(e,a),a.setShowData(e.showData),e.sections.map(a.addSection)},"populateDb"),ye={parse:p(async e=>{const a=await se("pie",e);z.debug(a),xe(a,L)},"parse")},we=p(e=>`
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
`,"getStyles"),Ae=we,De=p(e=>{const a=[...e.values()].reduce((s,o)=>s+o,0),f=[...e.entries()].map(([s,o])=>({label:s,value:o})).filter(s=>s.value/a*100>=1).sort((s,o)=>o.value-s.value);return ue().value(s=>s.value)(f)},"createPieArcs"),Ce=p((e,a,f,x)=>{z.debug(`rendering pie chart
`+e);const s=x.db,o=K(),l=X(s.getConfig(),o.pie),t=40,n=18,c=4,d=450,y=d,h=ee(a),u=h.append("g");u.attr("transform","translate("+y/2+","+d/2+")");const{themeVariables:i}=o;let[v]=te(i.pieOuterStrokeWidth);v??=2;const w=l.textPosition,m=Math.min(y,d)/2-t,C=R().innerRadius(0).outerRadius(m),$=R().innerRadius(m*w).outerRadius(m*w);u.append("circle").attr("cx",0).attr("cy",0).attr("r",m+v/2).attr("class","pieOuterCircle");const g=s.getSections(),A=De(g),D=[i.pie1,i.pie2,i.pie3,i.pie4,i.pie5,i.pie6,i.pie7,i.pie8,i.pie9,i.pie10,i.pie11,i.pie12];let b=0;g.forEach(r=>{b+=r});const G=A.filter(r=>(r.data.value/b*100).toFixed(0)!=="0"),k=le(D);u.selectAll("mySlices").data(G).enter().append("path").attr("d",C).attr("fill",r=>k(r.data.label)).attr("class","pieCircle"),u.selectAll("mySlices").data(G).enter().append("text").text(r=>(r.data.value/b*100).toFixed(0)+"%").attr("transform",r=>"translate("+$.centroid(r)+")").style("text-anchor","middle").attr("class","slice"),u.append("text").text(s.getDiagramTitle()).attr("x",0).attr("y",-400/2).attr("class","pieTitleText");const O=[...g.entries()].map(([r,M])=>({label:r,value:M})),E=u.selectAll(".legend").data(O).enter().append("g").attr("class","legend").attr("transform",(r,M)=>{const I=n+c,B=I*O.length/2,U=12*n,V=M*I-B;return"translate("+U+","+V+")"});E.append("rect").attr("width",n).attr("height",n).style("fill",r=>k(r.label)).style("stroke",r=>k(r.label)),E.append("text").attr("x",n+c).attr("y",n-c).text(r=>s.getShowData()?`${r.label} [${r.value}]`:r.label);const _=Math.max(...E.selectAll("text").nodes().map(r=>r?.getBoundingClientRect().width??0)),P=y+t+n+c+_;h.attr("viewBox",`0 0 ${P} ${d}`),ae(h,d,P,l.useMaxWidth)},"draw"),$e={draw:Ce},Ne={parser:ye,db:L,renderer:$e,styles:Ae};export{Ne as diagram};
