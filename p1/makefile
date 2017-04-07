OBJDIR := src/build
OBJS := $(addprefix $(OBJDIR)/,main.o lb.o hd.o wk.o hash.o list.o client.o)
BINDIR := bin


$(OBJDIR)/%.o : src/%.c
	gcc -g -c -o $@ $< -levent

all : bin/Project1

bin/Project1 : $(OBJS)
	gcc -g -o $@ $^ -levent -lpthread

bin/Project1 : | $(BINDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

$(OBJS) : | $(OBJDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -f $(OBJS) bin/Project1
	rm -f bin/*.log
