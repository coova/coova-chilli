// This script hereby is dedicated in the Public Domain
// as long as nobody else claims the copyright for it.
// origin: 2000-03-02 nospam@geht.net http://tools.geht.net/hexdump.html
// Use at own risk.
var last="", lasth="", inited=false;
var map_valtohex, map_hextochar, map_hextoval;
var hexes="0123456789ABCDEF";

// This needs JavaScript 1.2 because we need Char to Numeric value conversion
// Because there are 64K UniCode characters, this map does not cover all characters.
// We only cover ISO LATIN character codes.
function hexinit()
{
  var	i, h;

  map_valtohex	= new Array();
  map_hextochar	= new Array();
  map_hextoval	= new Array();

  for (i=0; i<256; i++)
    {
      h	= hexes.substr(i/16,1)+hexes.substr(i%16,1);
      map_valtohex[i]	= h;
      map_hextochar[h]	= String.fromCharCode(i);
      map_hextoval[h]	= i;
    }
  // this is a hack because JavaScript is unable to display \0
  map_hextochar["00"]	= String.fromCharCode(1);
  inited	= true;
}

// Usage: hexencode(variable) where variable contains data
// Note: hexdecode(hexencode(v))==v
function hexencode(a)
{
  var	s, l, c, i, j;
  
  if (!inited)
    hexinit();
  
  l	= "";
  c	= "";
  s	= "";
  for (i=0; i<a.length;	)
    {
      j	= a.charCodeAt(i);
      if (j>=32)
        c	= c + a.charAt(i);
      else
      	c	= c + ".";
      if (j<256)
        l	= l + map_valtohex[j] + " ";
      else
        l	= l + map_valtohex[Math.floor(j/256)]+map_valtohex[j%256] + " ";

      if (++i==a.length || l.length>45)
        {
          s	= s + l + "                                                  ".substr(l.length,50) + "! " + c + "\n";
          l	= "";
          c	= "";
        }
    }
  return s;
}

// Usage:
//  hexdecode("hh hh hh hh ...") where "hh" is hex codes
//  hexdecode("hhhhhhhh...") for hex codes without any space within
// Notes:
//  hexdecode(hexencode(v))==v
//  Limited support for unicode: hexdecode("hh hhhh hh hh hh ...")
//  It ignores everything behind a ! (usually ASCII dump)
//  It does not skip offset numbers (yet), you have to erase this yourself.
function hexdecode(a)
{
  var l,i,p,s,n,k,f,t,j,q;

  if (!inited)
    hexinit();

  // split into lines
  l	= a.split("\n");
  
  // elliminate comments from lines
  for (i=0; i<l.length; i++)
    {
      p	= l[i].indexOf("!");
      if (p>=0)
        l[i]	= l[i].substr(0,p);
    }

  s	= "";
  n	= 0;
  for (i=0; i<l.length; i++)
    {
      p	= l[i].toUpperCase();
      // weed out garbage and look for spaces
      k	= n;
      n	= 0;
      f	= 0;
      t	= "";
      for (j=0; j<p.length; j++)
        {
          k	= p.charAt(j);
       	  if (k==" ")
       	    f	= 1;
       	  else if (hexes.indexOf(k)>=0)
       	    {
       	      if (f && t!="")
       	        {
       	          n	= 1;
       	          t	= t + " ";
       	          f	= 0;
       	        }
       	      t	= t + k;
       	    }
        }
      if (i==l.length-1 && !n && k && t.length<=4)
      	n	= k;
//      alert("i"+i);
      // now process the line
      if (!n)
        // the fast case for no spaces in the line
        for (j=0; j<t.length; j+=2)
          {
            p	= t.substr(j,2);
            if (p.length==2)
              s	+= map_hextochar[p];
            else
              s	+= map_hextochar["0"+p];
          }
      else
        // we have spaces, look at the values more closely
        for (j=0; j<t.length; )
          {
//            alert("j"+j);
            p	= t.substr(j,5);
            k	= p.indexOf(" ");
            if (k<0)
              k	= 4;
            else
              j++;
            if (k>p.length)
              k	= p.length;
            j	+= k;
            switch (k)
              {
                case 1:
                  s	+= map_hextochar["0"+p.charAt(0)];
                  break;
                case 2:
                  s	+= map_hextochar[p.substr(0,2)];
                  break;
                case 3:
                  q	= map_hextoval["0"+p.charAt(0)]*256+map_hextoval[p.substr(1,2)];
                  if (q==0)
                    q	= 1;
                  s	+= String.fromCharCode(q);
                  break;
                case 4:
                  q	= map_hextoval[p.substr(0,2)]*256+map_hextoval[p.substr(2,2)];
                  if (q==0)
                    q	= 1;
                  s	+= String.fromCharCode(q);
                  break;
              }
          }
    }
  return s;
}