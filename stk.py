from tkinter import *
import re
import sqlite3
import os
import bcrypt
import time

admin_name = 'admin'

try_counter = 0


conn = sqlite3.connect('users.sqlite3')
c = conn.cursor()
c.execute('''CREATE TABLE users
            (uname text, passwd text, userblock integer, limitation integer)''')
c.execute("INSERT INTO users VALUES ('admin', ?, 0, 0)", (bcrypt.hashpw(''.encode('utf-8'), bcrypt.gensalt()), ))


def selectAlluserslist():
    c.execute("SELECT uname FROM users")
    alluserslist = c.fetchall()
    alluserslist1 = []
    for user in alluserslist:
        alluserslist1.append(user[0])
    return alluserslist1

def selectData(user):
    c.execute("SELECT * FROM users WHERE uname=?", (user,))
    userdata = c.fetchone()
    return userdata


def limitOnPasswd(passwd):
    pattern = r'[^A-Za-zА-Яа-я0-9]+'
    print(re.findall(pattern, passwd))
    if len(re.findall(pattern, passwd)) == 0:
        return TRUE
    else:
        return FALSE


def confirmPasswordBtn(event, user, first_new, second_new, msg):
    second_new = second_new.get()
    if first_new == second_new:
        c.execute("UPDATE users SET passwd=?  WHERE uname=?",
              (bcrypt.hashpw(second_new.encode('utf-8'), bcrypt.gensalt()), user))
        msg['text'] = 'Пароль изменен.'
    else:
        msg['text'] = 'Пароль не совпадает.\nВведите еще раз.'


def confirmPassword(user, first_new):
    window_second_passwd = Toplevel(root)
    window_second_passwd.title("Измененте пароля")
    window_second_passwd.minsize(width=400, height=200)
    second_new_password_l = Label(window_second_passwd, width=20, text='Новый пароль')
    second_new_password_e = Entry(window_second_passwd, width=20)
    confirm_password_b = Button(window_second_passwd, text="Смена пароля")
    msg_admin_window_passwd = Label(window_second_passwd, width=20)
    confirm_password_b.bind('<Button-1>',
                            lambda event, user=user, first_new=first_new, second_new=second_new_password_e, msg=msg_admin_window_passwd:
                            confirmPasswordBtn(event, user, first_new, second_new, msg))
    second_new_password_l.pack(), second_new_password_e.pack()
    confirm_password_b.pack(), msg_admin_window_passwd.pack()


def change_passwd(event, user, old_pwd, new, msg):
    old_passwd_n = old_pwd.get()
    new_passwd_n = new.get()
    old_db_passwd = selectData(user)[1]
    if bcrypt.hashpw(old_passwd_n.encode('utf-8'), old_db_passwd) == old_db_passwd:
        if selectData(user)[3] == 1 and not limitOnPasswd(new_passwd_n):
            msg['text'] = 'У Вас стоит ограничение на пароль.\nПароль не соответствует ограничениям.'
        else:
            msg['text'] = ''
            confirmPassword(user, new_passwd_n)
    else:
        msg['text'] = 'Неверный пароль'


def changePasswdBtn(event, lgn):
    admin_window_passwd = Toplevel(root)
    admin_window_passwd.title("Измененте пароля")
    admin_window_passwd.minsize(width=400, height=200)
    old_password_l = Label(admin_window_passwd, width=20, text='Старый пароль')
    old_password_e = Entry(admin_window_passwd, width=20)
    new_password_l = Label(admin_window_passwd, width=20, text='Новый пароль')
    new_password_e = Entry(admin_window_passwd, width=20)
    change_password_b = Button(admin_window_passwd, text="Смена пароля")
    msg_admin_window_passwd = Label(admin_window_passwd, width=30)
    change_password_b.bind('<Button-1>',
                           lambda event, l=lgn, old=old_password_e, new=new_password_e, msg=msg_admin_window_passwd: change_passwd(event, l, old, new, msg))
    old_password_l.pack(), old_password_e.pack(), new_password_l.pack()
    new_password_e.pack(), change_password_b.pack(), msg_admin_window_passwd.pack()


def usersListBtn(event):
    admin_window_userslist = Toplevel(root)
    admin_window_userslist.title("Список пользователей")
    admin_window_userslist.minsize(width=400, height=200)
    ulist = Label(admin_window_userslist, width=50)
    c.execute("SELECT * FROM users WHERE uname <> ?",  (admin_name,))
    alluserslist = c.fetchall()
    ulist['text'] = 'Пользователь\tБлокировка\tОграничения'
    for user in alluserslist:
        uname, passwd, block, limit = user
        ulist['text'] += '\n'+uname+'\t\t'+str(block)+'\t\t'+str(limit)
    ulist.pack()


def add_user(event, user, msg):
    user = user.get()
    if user not in selectAlluserslist():
        c.execute("INSERT INTO users VALUES (?, ?, 0, 0)", (user, bcrypt.hashpw(''.encode('utf-8'), bcrypt.gensalt())))
        msg['text'] = 'Пользователь добавлен.'
    else:
        msg['text'] = 'Пользователь с таким именем\n уже существует.'


def addUserBtn(event):
    admin_window_adduser = Toplevel(root)
    admin_window_adduser.title("Добавить пользователя")
    admin_window_adduser.minsize(width=400, height=200)
    adduser_name_l = Label(admin_window_adduser, width=20, text='Имя пользователя')
    adduser_name_e = Entry(admin_window_adduser, width=20)
    add_user_b = Button(admin_window_adduser, text="Добавить пользователя")
    msg_admin_window_adduser = Label(admin_window_adduser, width=20)
    add_user_b.bind('<Button-1>', lambda event, user=adduser_name_e, msg=msg_admin_window_adduser: add_user(event, user, msg))
    adduser_name_l.pack(), adduser_name_e.pack(), add_user_b.pack(), msg_admin_window_adduser.pack()


def block_user(event, user, msg):
    user = user.get()
    if user in selectAlluserslist():
        if selectData(user)[2] != 1:
            c.execute("UPDATE users SET userblock=1  WHERE uname=?",  (user, ))
            msg['text'] = 'Пользователь уже заблокирован.'
        else:
            msg['text'] = 'Пользователь уже заблокирован.'
    else:
        msg['text'] = 'Пользователь с таким именем\n не существует.'


def blockUserBtn(event):
    admin_window_blockuser = Toplevel(root)
    admin_window_blockuser.title("Забокировать пользователя")
    admin_window_blockuser.minsize(width=400, height=200)
    blockuser_name_l = Label(admin_window_blockuser, width=20, text='Имя пользователя')
    blockuser_name_e = Entry(admin_window_blockuser, width=20)
    block_user_b = Button(admin_window_blockuser, text="Заблокировать пользователя")
    msg_admin_window_blockuser = Label(admin_window_blockuser, width=20)
    block_user_b.bind('<Button-1>', lambda event, user=blockuser_name_e, msg=msg_admin_window_blockuser: block_user(event, user, msg))
    blockuser_name_l.pack(), blockuser_name_e.pack(), block_user_b.pack(), msg_admin_window_blockuser.pack()


def change_limitations(event, user, var, msg):
    var = var.get()
    user = user.get()
    print(user)
    if user in selectAlluserslist() and user != admin_name:
        if var != selectData(user)[3]:
            c.execute("UPDATE users SET limitation=?  WHERE uname=?", (var, user))
            msg['text'] = 'Ограничения изменены.'
        else:
            if var == 1:
                msg['text'] = 'У пользователя уже\nустановлены ограничения.'
            else:
                msg['text'] = 'У пользователя и так \nне установлены ограничения.'
    else:
        msg['text'] = 'Пользователь с таким именем\n не существует.'


def changeLimitationsBtn(event):
    admin_window_limitations = Toplevel(root)
    admin_window_limitations.title("Изменить ограничения на пароль")
    admin_window_limitations.minsize(width=400, height=200)
    user_name_l = Label(admin_window_limitations, width=20, text='Имя пользователя')
    user_name_e = Entry(admin_window_limitations, width=20)
    var = IntVar()
    var.set(1)
    turn_on = Radiobutton(admin_window_limitations, text="Включить", variable=var, value=1)
    turn_off = Radiobutton(admin_window_limitations, text="Отключить", variable=var, value=0)
    apply_limitation_b = Button(admin_window_limitations, text="Применить")
    msg_admin_window_limitations = Label(admin_window_limitations, width=30)
    print(user_name_e)
    apply_limitation_b.bind('<Button-1>',
                      lambda event, user=user_name_e, v=var, msg=msg_admin_window_limitations: change_limitations(event, user, var, msg))
    user_name_l.pack(), user_name_e.pack(), turn_on.pack(), turn_off.pack()
    apply_limitation_b.pack(), msg_admin_window_limitations.pack()


def window_create(lgn):
    admin_window = Toplevel(root)
    admin_window.title("Окно администратора")
    admin_window.minsize(width=400, height=200)
    change_password_b = Button(admin_window, text="Смена пароля")
    users_list_b = Button(admin_window, text="Список пользователей")
    add_user_b = Button(admin_window, text="Добавить пользователя")
    block_user_b = Button(admin_window, text="Блокировать пользователя")
    change_limitations_b = Button(admin_window, text="Вкл/выкл ограничения на пароль")
    exit_b = Button(admin_window, text="Завершить программу", command=root.destroy)
    change_password_b.bind('<Button-1>', lambda event, l=lgn: changePasswdBtn(event, l))
    if lgn == 'admin':
        admin_window.title("Окно администратора")
        users_list_b.bind('<Button-1>', usersListBtn)
        add_user_b.bind('<Button-1>', addUserBtn)
        block_user_b.bind('<Button-1>', blockUserBtn)
        change_limitations_b.bind('<Button-1>', changeLimitationsBtn)
    else:
        admin_window.title("Окно пользователя")
        users_list_b['state'] = DISABLED
        add_user_b['state'] = DISABLED
        block_user_b['state'] = DISABLED
        change_limitations_b['state'] = DISABLED
    change_password_b.pack()
    users_list_b.pack()
    add_user_b.pack()
    block_user_b.pack()
    change_limitations_b.pack()
    exit_b.pack()


def enterBtn(event):
    global try_counter
    print(try_counter)
    if try_counter == 3:
        msg['text'] = 'Неправильный пароль.\nВведите пароль повторно.'
        time.sleep(5)
        root.quit()
    lgn = login.get()
    pwd = password.get()
    alluserslist = selectAlluserslist()
    print(lgn)
    # ADMIN
    if lgn == 'admin':
        if bcrypt.hashpw(pwd.encode('utf-8'), selectData(lgn)[1]) == selectData(lgn)[1]:
            try_counter = 0
            window_create(lgn)
        else:
            try_counter += 1
            msg['text'] = 'Неправильный пароль.\nВведите пароль повторно.'
    # USER
    elif lgn != 'admin' and lgn in alluserslist and selectData(lgn)[2] == 0:
        if bcrypt.hashpw(pwd.encode('utf-8'), selectData(lgn)[1]) == selectData(lgn)[1]:
            try_counter = 0
            window_create(lgn)
        else:
            try_counter += 1
            msg['text'] = 'Неправильный пароль.\nВведите пароль повторно.'
    elif lgn in alluserslist and selectData(lgn)[2] == 1:
        msg['text'] = 'Вход не выполнен.\nВы заблокированы.'
    else:
        msg['text'] = 'Неправильное имя пользователя.\nВведите имя пользователя повторно.'


def about():
    about = Toplevel(root)
    lab = Label(about, text="Дарья Лях")
    lab.pack()


root = Tk()
root.minsize(width=200, height=100)
m = Menu(root)
root.config(menu=m)
fm = Menu(m)
m.add_cascade(label="Справка", menu=fm)
fm.add_command(label="О программе..", command=about)
login = Entry(width=20)
password = Entry(width=20, show='*')
enter = Button(text="Вход")
msg = Label(width=30)
enter.bind('<Button-1>', enterBtn)
login.pack()
password.pack()
enter.pack()
msg.pack()
root.mainloop()

conn.close()
os.remove('users.sqlite3')
