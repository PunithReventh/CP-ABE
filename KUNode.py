class Tree:
    def __init__(self, n_users, h=1):
        """
        Initializes a tree with height h
        vertices numbered in increasing order from
        left to right and top to bottom
                    7
                5       6
              1   2   3   4
        """
        self.height = h
        self.root = 2**(h+1)-1
        self.Dict = dict()
        self.RL = []
        self.__build_tree()
        self.Dict[self.root][3] = "G"
        self.n_users = n_users

    def __build_tree(self):
        count = 2**self.height + 1
        height = self.height - 1
        #print(count, height)
        for i in range(1, 2**self.height + 1):
            self.Dict[i] = [None, None, None, "B", None]
        lcount = 1
        #print(self.Dict)
        #print(lcount)
        while count != self.root+1:
            flow = lcount
            #print(flow)
            while flow - lcount != 2**(height+1):
                self.Dict[count] = [flow, flow + 1, None, "B", None]
                self.Dict[flow][2] = count
                self.Dict[flow + 1][2] = count
                count += 1
                flow += 2
                #print(self.Dict)
                #print("count = %d flow = %d lcount = %d" %(count, flow, lcount))
            height -= 1
            lcount = flow 


    def revoke(self, user):
        assert user <= 2**self.height, "User not present"
        assert user <= self.n_users, "User not present"
        curr_node = self.Dict[user]
        assert (curr_node[0], curr_node[1]) == (None, None)
        curr_node[3] = "R"
        curr_parent = curr_node[2]
        self.RL.append(user) 

        while curr_parent != None:
            curr_node = curr_parent
            node = self.Dict[curr_node]
            node[3] = "R"
            if self.Dict[node[0]][3] == "B":
                self.Dict[node[0]][3] = "G"
            elif self.Dict[node[1]][3] == "B":
                self.Dict[node[1]][3] = "G"
            curr_parent = node[2]


    def get_sets(self):
        X, Y = list(), list()
        for node in self.Dict:
            q = self.Dict[node]
            if q[3] == "R":
                X.append(node)
            elif q[3] == "G":
                Y.append(node)
        return X, Y


    def Path(self, user):
        assert user <= 2**self.height, "User not present"
        assert user <= self.n_users, "User not present"
        curr_node = self.Dict[user]
        assert (curr_node[0], curr_node[1]) == (None, None)
        path = [user]
        parent = curr_node[2]

        while parent != None:
            curr_node = parent
            path.append(curr_node)
            parent = self.Dict[curr_node][2]

        return path


    def addUser(self, nos=1):
        assert self.n_users + nos <= 2**self.height, "Can't add so many users"
        self.n_users += nos


    def getRL(self):
        return self.RL
        
        
if __name__ == "__main__":
    a = Tree(5, 3)
    #print(a.Dict)
    X, Y = a.get_sets()
    path = set(a.Path(2))
    common = path.intersection(set(Y))
    print("Common ", common)
    for w in common:
        print(int(w))
    print("X = {} \nY = {}".format(X, Y))
    a.revoke(3)
    X, Y = a.get_sets()
    print("X = {} \nY = {}".format(X, Y))
    a.addUser()
    a.revoke(6)
    path3 = a.Path(3)
    print("Path for 3 =", path3)
    path6 = a.Path(6)
    print("Path for 6 =", path6)
    X, Y = a.get_sets()
    print("X = {} \nY = {}".format(X, Y))
    a.addUser(3)
    Revoke_List = a.getRL()
    print(Revoke_List)
