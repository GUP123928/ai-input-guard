# -*- coding: utf-8 -*-
"""让测试无需安装即可 import 本包（pytest 从仓库根运行时）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
