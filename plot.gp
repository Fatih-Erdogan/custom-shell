set terminal pngcairo size 800,600
set output ARG2

### tree diagram with gnuplot
reset session
 
#PID  PPID  IsEldest  CreationTime
input_file = ARG1


 
# put datablock into strings
IDs = Parents = IsEldests = CreationTimes = ''
set table $Dummy
    plot input_file every ::1 u (IDs = IDs.strcol(1).' '): \
                 (Parents = Parents.strcol(2).' '): \
                 (IsEldests = IsEldests.strcol(3).' '): \
                 (CreationTimes = CreationTimes.strcol(4).' ') w table
unset table


 
# Top node has no parent ID 'NaN'
Start(n) = int(sum [i=1:words(Parents)] (word(Parents,i) eq 'NaN' ? int(word(IDs,i)) : 0))

# Determine color
NodeColor(n) = word(IsEldests, ItemIdx(IDs, n)) == '1' ? 0xff0000 : 0x00ff00

# get list index by ID
ItemIdx(s,n) = n == n ? (tmp=NaN, sum [i=1:words(s)] ((word(s,i)) == n ? (tmp=i,0) : 0), tmp) : NaN
 
# get parent of ID n
Parent(n) = word(Parents,ItemIdx(IDs,n))
 
# get level of ID n, recursive function
Level(n) = n == n ? Parent(n)>0 ? Level(Parent(n))-1 : 0 : NaN
 
# get number of children of ID n
ChildCount(n) = int(sum [i=1:words(Parents)] (word(Parents,i)==n))
 
# Create child list of ID n
ChildList(n) = (Ch = ' ', sum [i=1:words(IDs)] (word(Parents,i)==n ? (Ch = Ch.word(IDs,i).' ',1) : (Ch,0) ), Ch )
 
# m-th child of ID n
Child(n,m) = word(ChildList(n),m)
 
# List of leaves, recursive function
LeafList(n) = (LL='', ChildCount(n)==0 ? LL=LL.n.' ' : sum [i=1:ChildCount(n)] (LL=LL.LeafList(Child(n,i)), 0),LL)
 
# create list of all leaves
LeafAll = LeafList(Start(0))
 
# get x-position of ID n, recursive function
XPos(n) = ChildCount(n) == 0 ? ItemIdx(LeafAll,n) : (sum [i=1:ChildCount(n)] (XPos(Child(n,i))))/(ChildCount(n))
 
# create the tree datablock for plotting
set print $Tree
    do for [j=1:words(IDs)] {
        n = int(word(IDs,j))
        print sprintf("% 3d % 7.2f % 4d %s@%s", n, XPos(n), Level(n), word(IDs,j), word(CreationTimes,j))
    }
set print
 
# get x and y distance from ID n to its parent
dx(n) = XPos(Parent(int(n))) - XPos(int(n))
dy(n) = Level(Parent(int(n))) - Level(int(n))
 
unset border
unset tics
set offsets 0.25, 0.25, 0.25, 0.25

plot $Tree u 2:3:(dx($1)):(dy($1)) w vec nohead ls -1 not, \
     '' u 2:3:(NodeColor($1)) w p pt 7 ps 2.5 lc rgb var not, \
     '' u 2:3:(sprintf("%s\n%s", word(IDs, ItemIdx(IDs, $1)), word(CreationTimes, ItemIdx(IDs, $1)))) w labels offset 0,0 center font ",7" not

