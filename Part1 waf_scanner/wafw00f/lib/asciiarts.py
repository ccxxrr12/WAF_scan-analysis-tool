#!/usr/bin/env python3
'''
版权所有 (C) 2024, WAFW00F 开发者。
请参阅 LICENSE 文件以了解复制权限。

此文件定义了用于终端输出的 ASCII 艺术图案和颜色。
'''

from dataclasses import dataclass
from random import randint

from wafw00f import __version__


@dataclass
class Color:
    '''
    定义 ANSI 颜色。
    '''
    W: str = '\033[1;97m'  # 白色
    Y: str = '\033[1;93m'  # 黄色
    G: str = '\033[1;92m'  # 绿色
    R: str = '\033[1;91m'  # 红色
    B: str = '\033[1;94m'  # 蓝色
    C: str = '\033[1;96m'  # 青色
    E: str = '\033[0m'     # 重置颜色

    @classmethod
    def disable(cls):
        '''
        禁用所有颜色。
        '''
        cls.W = ''
        cls.Y = ''
        cls.G = ''
        cls.R = ''
        cls.B = ''
        cls.C = ''
        cls.E = ''

    @classmethod
    def unpack(cls):
        '''
        解包并返回颜色值。
        示例：
        (W,Y,G,R,B,C,E) = Color.unpack()
        '''
        return (
            cls.W,
            cls.Y,
            cls.G,
            cls.R,
            cls.B,
            cls.C,
            cls.E
        )


def randomArt():
    '''
    随机返回一个 ASCII 艺术图案。

    返回：
        str: ASCII 艺术图案。
    '''
    (W,Y,G,R,B,C,E) = Color.unpack()

    woof = '''
                   '''+W+'''______
                  '''+W+'''/      \\
                 '''+W+'''(  Woof! )
                  '''+W+r'''\  ____/                      '''+R+''')
                  '''+W+''',,                           '''+R+''') ('''+Y+'''_
             '''+Y+'''.-. '''+W+'''-    '''+G+'''_______                 '''+R+'''( '''+Y+'''|__|
            '''+Y+'''()``; '''+G+'''|==|_______)                '''+R+'''.)'''+Y+'''|__|
            '''+Y+'''/ ('        '''+G+r'''/|\                  '''+R+'''(  '''+Y+'''|__|
        '''+Y+'''(  /  )       '''+G+r''' / | \                  '''+R+'''. '''+Y+'''|__|
         '''+Y+r'''\(_)_))      '''+G+r'''/  |  \                   '''+Y+'''|__|'''+E+'''

                    '''+C+'~ WAFW00F : '+B+'v'+__version__+''' ~'''+W+'''
    The Web Application Firewall Fingerprinting Toolkit
    '''+E

    w00f = '''
                '''+W+'''______
               '''+W+'''/      \\
              '''+W+'''(  W00f! )
               '''+W+r'''\  ____/
               '''+W+''',,    '''+G+'''__            '''+Y+'''404 Hack Not Found
           '''+C+'''|`-.__   '''+G+'''/ /                     '''+R+''' __     __
           '''+C+'''/"  _/  '''+G+'''/_/                       '''+R+r'''\ \   / /
          '''+B+'''*===*    '''+G+'''/                          '''+R+r'''\ \_/ /  '''+Y+'''405 Not Allowed
         '''+C+'''/     )__//                           '''+R+r'''\   /
    '''+C+'''/|  /     /---`                        '''+Y+'''403 Forbidden
    '''+C+r'''\\/`   \ |                                 '''+R+'''/ _ \\
    '''+C+r'''`\    /_\\_              '''+Y+'''502 Bad Gateway  '''+R+r'''/ / \ \  '''+Y+'''500 Internal Error
      '''+C+'''`_____``-`                             '''+R+r'''/_/   \_\\

                        '''+C+'~ WAFW00F : '+B+'v'+__version__+''' ~'''+W+'''
        The Web Application Firewall Fingerprinting Toolkit
    '''+E

    wo0f = r'''
                 ?              ,.   (   .      )        .      "
         __        ??          ("     )  )'     ,'        )  . (`     '`
    (___()'`;   ???          .; )  ' (( (" )    ;(,     ((  (  ;)  "  )")
    /,___ /`                 _"., ,._'_.,)_(..,( . )_  _' )_') (. _..( ' )
    \\   \\                 |____|____|____|____|____|____|____|____|____|

                                ~ WAFW00F : v'''+__version__+''' ~
                    ~ Sniffing Web Application Firewalls since 2014 ~
'''

    arts = [woof, w00f, wo0f]
    return arts[randint(0, len(arts)-1)]
