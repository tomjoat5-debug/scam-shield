"""识别引擎测试。

诈骗用例按公开常见套路自己编写；良性用例覆盖日常真实场景。
口径：单个普通词不触发高风险；良性文本必须判低风险。
"""

import unittest

from scam_shield.engine import analyze

# ---- 诈骗用例：每类一个，期望高 / 极高风险 ----

SCAM_CASES = [
    (
        "impersonate_police",
        "您好，这里是市公安局，您涉嫌一起洗钱案件，名下银行卡已被冻结。"
        "请立即将资金转入安全账户配合调查，案件保密，不要告诉任何人，否则将冻结账户。",
        "极高",
    ),
    (
        "impersonate_family",
        "我是你表哥，换了新号码，以前那个打不通了。我这边出车祸在医院，"
        "急用钱，先转给我两万块，千万不要跟家里说。",
        "极高",
    ),
    (
        "fake_rebate",
        "在家动动手指就能赚钱，淘宝刷单返利，日结佣金，单单返现。"
        "先垫付本金，完成任务后本金加佣金一起返还，垫付越多赚得越多。",
        "极高",
    ),
    (
        "fake_refund",
        "您好，我是淘宝客服，您购买的商品存在质量问题，现为您办理退款。"
        "请提供您的银行卡号，并把收到的验证码告诉我，退款将在十分钟内到账。",
        "极高",
    ),
    (
        "investment_pig",
        "老师带单，稳赚不赔，内幕消息，跟着操作一周收益翻倍。"
        "我们有个投资群，都是内部消息，现在入金还来得及，保证盈利，错过就没有了。",
        "极高",
    ),
    (
        "fake_prize",
        "恭喜您中奖了！您被抽中为本期幸运用户，获得一台最新款手机。"
        "请先缴纳500元保证金和税费，交完后奖品立即寄出，兑奖链接已发给您。",
        "极高",
    ),
    (
        "impersonate_boss",
        "小王，我是张总，换了新微信。我现在在开会，不方便接电话，"
        "你先帮我垫付一笔送礼的钱，六千块，事情比较急，不要声张，回头我还你。",
        "极高",
    ),
    (
        "fake_flight",
        "尊敬的旅客，您预订的航班因机械故障取消，请及时办理退改签。"
        "退票手续费200元，请拨打客服电话400-888-XXXX办理，或点击链接操作。",
        "极高",
    ),
    (
        "fake_loan",
        "您好，这里是网贷客服，您名下有一笔网贷未注销，会影响征信。"
        "请立即办理注销，否则征信不良将影响您贷款买房。注销需缴纳手续费，请按提示转账。",
        "极高",
    ),
    (
        "fake_express",
        "您的快递在运输途中丢失，现为您办理丢件理赔，理赔金800元。"
        "请扫码领取理赔金，或点击链接填写银行卡信息，逾期将无法理赔。",
        "极高",
    ),
    (
        "fake_parttime",
        "招聘兼职抖音点赞员，在家动动手指，日结工资，一天能赚200元。"
        "入职需先交300元押金和会费，交完立即安排任务，名额有限。",
        "极高",
    ),
]

# ---- 良性用例：必须判低风险 ----

BENIGN_CASES = [
    "【工商银行】您尾号1234的储蓄卡于11月11日10:20收到转账5000.00元，余额12500.00元。",
    "【菜鸟】您的快递已送达丰巢快递柜，请凭取件码123456及时取件。",
    "【支付宝】您的验证码是123456，5分钟内有效，请勿泄露给他人。",
    "妈，今天降温了，多穿点衣服，晚上回家吃饭，我买了你爱吃的鱼。",
    "下午三点开会，记得带上周的报表，会议室在三楼。",
    "各位家长，明天上午九点开家长会，请准时参加，地点在学校大礼堂。",
    "【电费】您本月电费128.50元，请于11月20日前缴纳，逾期将产生滞纳金。",
    "今晚一起吃饭吗？老地方川菜馆，六点见，我请客。",
    "【建设银行】您尾号5678的信用卡于11月11日支出128.00元，当前余额4520.30元。",
    "您的包裹正在派送中，预计今天送达，请保持电话畅通。",
]


class TestScamCases(unittest.TestCase):
    def test_each_category_detected(self):
        for category_id, text, expected_risk in SCAM_CASES:
            with self.subTest(category=category_id):
                result = analyze(text)
                self.assertEqual(result["category_id"], category_id)
                self.assertEqual(result["risk"], expected_risk)
                self.assertTrue(result["signals"])
                self.assertTrue(result["advice"])

    def test_ai_clone_checklist_attached_on_call_impersonation(self):
        text = (
            "喂，是我，你儿子。我手机丢了，借别人手机给你打电话。"
            "我这边出了点事，急用钱，你先转我三万块，回家再跟你解释。"
        )
        result = analyze(text)
        self.assertEqual(result["category_id"], "impersonate_family")
        self.assertIn(result["risk"], ("高", "极高"))
        self.assertIsNotNone(result["ai_clone_checklist"])
        self.assertIn("先挂断", result["ai_clone_checklist"][0])

    def test_no_ai_clone_checklist_without_call_context(self):
        text = SCAM_CASES[0][1]  # 冒充公检法，纯文字，无电话/视频语境
        result = analyze(text)
        self.assertIsNone(result["ai_clone_checklist"])


class TestBenignCases(unittest.TestCase):
    def test_benign_is_low_risk(self):
        for text in BENIGN_CASES:
            with self.subTest(text=text[:20]):
                result = analyze(text)
                self.assertEqual(result["risk"], "低")
                self.assertIsNone(result["category_id"])

    def test_single_ordinary_word_does_not_trigger_high_risk(self):
        # 单个普通词（退款、中奖）出现在正常语境里，不应判高风险
        self.assertEqual(analyze("你上次买的衣服退款到账了吗？")["risk"], "低")
        self.assertEqual(analyze("恭喜你中奖了，奖品是公司发的月饼")["risk"], "低")


class TestEdgeCases(unittest.TestCase):
    def test_empty_text(self):
        result = analyze("")
        self.assertEqual(result["risk"], "低")
        self.assertIsNone(result["category_id"])
        self.assertIn("未输入文本", result["note"])

    def test_very_short_text(self):
        result = analyze("你好")
        self.assertEqual(result["risk"], "低")
        self.assertIn("过短", result["note"])

    def test_mixed_benign_and_scam(self):
        # 正常银行短信后面跟了一段诈骗话术：诈骗部分仍应被检出
        text = (
            "【工商银行】您尾号1234的储蓄卡收到转账5000元，余额12500元。"
            "另外提醒您，您的账户涉嫌洗钱，请将资金转入安全账户配合调查。"
        )
        result = analyze(text)
        self.assertIn(result["risk"], ("高", "极高"))
        self.assertEqual(result["category_id"], "impersonate_police")

    def test_result_structure(self):
        result = analyze("你好")
        for key in (
            "risk",
            "category_id",
            "category_name",
            "score",
            "signals",
            "benign_notes",
            "advice",
            "ai_clone_checklist",
            "note",
        ):
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
